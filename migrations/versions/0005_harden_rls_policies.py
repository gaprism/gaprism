"""Remove recursive RLS lookups and enforce case-scoped runtime access.

Revision ID: 0005_harden_rls_policies
Revises: 0004_checks_findings_annotations
Create Date: 2026-10-02 14:00:00.000000

The helper functions deliberately derive the actor from transaction-local settings.
They never accept a caller-selected user ID.  Their owner must be the dedicated
migration role with BYPASSRLS so the functions can inspect the small access-control
tables without recursively invoking their policies.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_harden_rls_policies"
down_revision: str | None = "0004_checks_findings_annotations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


CONTENT_TABLES = (
    "assessment",
    "assessment_grant",
    "report",
    "report_version",
    "report_grant",
    "membership",
    "workspace",
    "scan_run",
    "job",
    "job_attempt",
    "provider_quota",
    "quota_reservation",
    "host",
    "run_host",
    "ct_name_observation",
    "check_result",
    "finding",
    "finding_annotation",
)


def _drop_existing_policies() -> None:
    policy_names = {
        "assessment": ("assessment_isolation_policy",),
        "assessment_grant": ("assessment_grant_isolation_policy",),
        "report": ("report_isolation_policy",),
        "report_version": ("report_version_isolation_policy",),
        "report_grant": ("report_grant_isolation_policy",),
        "membership": ("membership_isolation_policy",),
        "workspace": ("workspace_isolation_policy",),
        "scan_run": ("scan_run_isolation_policy",),
        "job": ("job_isolation_policy",),
        "job_attempt": ("job_attempt_isolation_policy",),
        "provider_quota": ("provider_quota_isolation_policy",),
        "quota_reservation": ("quota_reservation_isolation_policy",),
        "host": ("host_workspace_isolation_policy", "host_assessment_access_policy"),
        "run_host": (
            "run_host_workspace_isolation_policy",
            "run_host_assessment_access_policy",
        ),
        "ct_name_observation": (
            "ct_name_observation_workspace_isolation_policy",
            "ct_name_observation_assessment_access_policy",
        ),
        "check_result": ("check_result_tenant_isolation",),
        "finding": ("finding_tenant_isolation",),
        "finding_annotation": ("finding_annotation_tenant_isolation",),
    }
    for table, names in policy_names.items():
        for name in names:
            op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")


def _create_helpers() -> None:
    op.execute(
        """
        DO $migration_role_check$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_roles
                WHERE rolname = current_user
                  AND (rolsuper OR rolbypassrls)
            ) THEN
                RAISE EXCEPTION
                    'RLS helper owner % must have BYPASSRLS (or be superuser); '
                    'use the dedicated migration role', current_user;
            END IF;
        END
        $migration_role_check$;
        """
    )

    op.execute(
        """
        CREATE FUNCTION public.app_has_workspace_membership(target_workspace uuid)
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT EXISTS (
                SELECT 1
                FROM public.membership AS m
                JOIN public.workspace AS w ON w.id = m.workspace_id
                JOIN public."user" AS u ON u.id = m.user_id
                WHERE m.workspace_id = target_workspace
                  AND m.user_id =
                      NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid
                  AND m.active
                  AND w.enabled
                  AND u.active
                  AND target_workspace =
                      NULLIF(pg_catalog.current_setting('app.workspace_id', true), '')::uuid
            );
        $function$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.app_is_workspace_admin(target_workspace uuid)
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT EXISTS (
                SELECT 1
                FROM public.membership AS m
                JOIN public.workspace AS w ON w.id = m.workspace_id
                JOIN public."user" AS u ON u.id = m.user_id
                WHERE m.workspace_id = target_workspace
                  AND m.user_id =
                      NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid
                  AND m.role = 'admin'
                  AND m.active
                  AND w.enabled
                  AND u.active
                  AND target_workspace =
                      NULLIF(pg_catalog.current_setting('app.workspace_id', true), '')::uuid
            );
        $function$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.app_has_assessment_role(
            target_assessment uuid,
            target_workspace uuid,
            allowed_roles text[] DEFAULT NULL
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT public.app_has_workspace_membership(target_workspace)
               AND EXISTS (
                    SELECT 1
                    FROM public.assessment AS a
                    WHERE a.id = target_assessment
                      AND a.workspace_id = target_workspace
                      AND (
                          (
                              a.owner_user_id = NULLIF(
                                  pg_catalog.current_setting('app.user_id', true), ''
                              )::uuid
                              AND (
                                  allowed_roles IS NULL
                                  OR 'owner' = ANY(allowed_roles)
                              )
                          )
                          OR EXISTS (
                              SELECT 1
                              FROM public.assessment_grant AS ag
                              WHERE ag.assessment_id = a.id
                                AND ag.workspace_id = a.workspace_id
                                AND ag.user_id = NULLIF(
                                    pg_catalog.current_setting('app.user_id', true), ''
                                )::uuid
                                AND ag.revoked_at IS NULL
                                AND (ag.expires_at IS NULL OR ag.expires_at > now())
                                AND (
                                    allowed_roles IS NULL
                                    OR ag.role = ANY(allowed_roles)
                                )
                          )
                      )
                );
        $function$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.app_has_report_version_access(
            target_report_version uuid,
            target_workspace uuid
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT EXISTS (
                SELECT 1
                FROM public.report_version AS rv
                WHERE rv.id = target_report_version
                  AND rv.workspace_id = target_workspace
                  AND (rv.expires_at IS NULL OR rv.expires_at > now())
                  AND (
                      public.app_has_assessment_role(
                          rv.assessment_id,
                          rv.workspace_id,
                          NULL::text[]
                      )
                      OR (
                          rv.state = 'issued'
                          AND public.app_has_workspace_membership(rv.workspace_id)
                          AND EXISTS (
                              SELECT 1
                              FROM public.report_grant AS rg
                              WHERE rg.report_version_id = rv.id
                                AND rg.workspace_id = rv.workspace_id
                                AND rg.user_id = NULLIF(
                                    pg_catalog.current_setting('app.user_id', true), ''
                                )::uuid
                                AND rg.revoked_at IS NULL
                                AND (rg.expires_at IS NULL OR rg.expires_at > now())
                          )
                      )
                  )
            );
        $function$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.app_can_manage_assessment_grant(
            target_assessment uuid,
            target_workspace uuid,
            target_recipient uuid
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT public.app_has_assessment_role(
                       target_assessment,
                       target_workspace,
                       ARRAY['owner']::text[]
                   )
               AND EXISTS (
                    SELECT 1
                    FROM public.membership AS m
                    JOIN public."user" AS u ON u.id = m.user_id
                    WHERE m.workspace_id = target_workspace
                      AND m.user_id = target_recipient
                      AND m.active
                      AND u.active
                );
        $function$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.app_can_manage_report_grant(
            target_report_version uuid,
            target_workspace uuid,
            target_recipient uuid
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT EXISTS (
                SELECT 1
                FROM public.report_version AS rv
                WHERE rv.id = target_report_version
                  AND rv.workspace_id = target_workspace
                  AND rv.state = 'issued'
                  AND (rv.expires_at IS NULL OR rv.expires_at > now())
                  AND public.app_has_assessment_role(
                      rv.assessment_id,
                      rv.workspace_id,
                      ARRAY['owner']::text[]
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM public.membership AS m
                      JOIN public."user" AS u ON u.id = m.user_id
                      WHERE m.workspace_id = target_workspace
                        AND m.user_id = target_recipient
                        AND m.active
                        AND u.active
                  )
            );
        $function$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.app_has_job_role(
            target_job uuid,
            allowed_roles text[] DEFAULT NULL
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET row_security = off
        AS $function$
            SELECT EXISTS (
                SELECT 1
                FROM public.job AS j
                WHERE j.id = target_job
                  AND public.app_has_assessment_role(
                      j.assessment_id,
                      j.workspace_id,
                      allowed_roles
                  )
            );
        $function$;
        """
    )

    for signature in (
        "app_has_workspace_membership(uuid)",
        "app_is_workspace_admin(uuid)",
        "app_has_assessment_role(uuid, uuid, text[])",
        "app_has_report_version_access(uuid, uuid)",
        "app_can_manage_assessment_grant(uuid, uuid, uuid)",
        "app_can_manage_report_grant(uuid, uuid, uuid)",
        "app_has_job_role(uuid, text[])",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")


def _create_identity_policies() -> None:
    op.execute(
        """
        CREATE POLICY assessment_select ON assessment FOR SELECT
        USING (public.app_has_assessment_role(id, workspace_id, NULL::text[]));
        CREATE POLICY assessment_insert ON assessment FOR INSERT
        WITH CHECK (
            public.app_has_workspace_membership(workspace_id)
            AND owner_user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
            AND created_by = NULLIF(current_setting('app.user_id', true), '')::uuid
        );
        CREATE POLICY assessment_update ON assessment FOR UPDATE
        USING (public.app_has_assessment_role(id, workspace_id, ARRAY['owner']::text[]))
        WITH CHECK (public.app_has_assessment_role(id, workspace_id, ARRAY['owner']::text[]));
        CREATE POLICY assessment_delete ON assessment FOR DELETE
        USING (public.app_has_assessment_role(id, workspace_id, ARRAY['owner']::text[]));
        """
    )
    op.execute(
        """
        CREATE POLICY assessment_grant_select ON assessment_grant FOR SELECT
        USING (
            workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
            AND (
                user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                OR public.app_has_assessment_role(
                    assessment_id, workspace_id, ARRAY['owner']::text[]
                )
            )
        );
        CREATE POLICY assessment_grant_insert ON assessment_grant FOR INSERT
        WITH CHECK (
            public.app_can_manage_assessment_grant(
                assessment_id, workspace_id, user_id
            )
            AND granted_by = NULLIF(current_setting('app.user_id', true), '')::uuid
        );
        CREATE POLICY assessment_grant_update ON assessment_grant FOR UPDATE
        USING (
            public.app_has_assessment_role(
                assessment_id, workspace_id, ARRAY['owner']::text[]
            )
        )
        WITH CHECK (
            public.app_can_manage_assessment_grant(
                assessment_id, workspace_id, user_id
            )
        );
        CREATE POLICY assessment_grant_delete ON assessment_grant FOR DELETE
        USING (
            public.app_has_assessment_role(
                assessment_id, workspace_id, ARRAY['owner']::text[]
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY report_select ON report FOR SELECT
        USING (public.app_has_assessment_role(assessment_id, workspace_id, NULL::text[]));
        CREATE POLICY report_mutate ON report FOR ALL
        USING (
            public.app_has_assessment_role(
                assessment_id, workspace_id, ARRAY['owner', 'analyst']::text[]
            )
        )
        WITH CHECK (
            public.app_has_assessment_role(
                assessment_id, workspace_id, ARRAY['owner', 'analyst']::text[]
            )
        );
        CREATE POLICY report_version_select ON report_version FOR SELECT
        USING (public.app_has_report_version_access(id, workspace_id));
        CREATE POLICY report_version_mutate ON report_version FOR ALL
        USING (
            public.app_has_assessment_role(
                assessment_id, workspace_id, ARRAY['owner', 'analyst']::text[]
            )
        )
        WITH CHECK (
            public.app_has_assessment_role(
                assessment_id, workspace_id, ARRAY['owner', 'analyst']::text[]
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY report_grant_select ON report_grant FOR SELECT
        USING (
            workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
            AND (
                user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                OR public.app_can_manage_report_grant(
                    report_version_id, workspace_id, user_id
                )
            )
        );
        CREATE POLICY report_grant_insert ON report_grant FOR INSERT
        WITH CHECK (
            public.app_can_manage_report_grant(
                report_version_id, workspace_id, user_id
            )
            AND granted_by = NULLIF(current_setting('app.user_id', true), '')::uuid
        );
        CREATE POLICY report_grant_update ON report_grant FOR UPDATE
        USING (
            public.app_can_manage_report_grant(
                report_version_id, workspace_id, user_id
            )
        )
        WITH CHECK (
            public.app_can_manage_report_grant(
                report_version_id, workspace_id, user_id
            )
        );
        CREATE POLICY report_grant_delete ON report_grant FOR DELETE
        USING (
            public.app_can_manage_report_grant(
                report_version_id, workspace_id, user_id
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY membership_select ON membership FOR SELECT
        USING (
            (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
             AND public.app_has_workspace_membership(workspace_id))
            OR public.app_is_workspace_admin(workspace_id)
        );
        CREATE POLICY membership_mutate ON membership FOR ALL
        USING (public.app_is_workspace_admin(workspace_id))
        WITH CHECK (public.app_is_workspace_admin(workspace_id));
        CREATE POLICY workspace_select ON workspace FOR SELECT
        USING (public.app_has_workspace_membership(id));
        CREATE POLICY workspace_update ON workspace FOR UPDATE
        USING (public.app_is_workspace_admin(id))
        WITH CHECK (public.app_is_workspace_admin(id));
        """
    )


def _create_case_data_policies() -> None:
    for table in ("scan_run", "job"):
        op.execute(
            f"""
            CREATE POLICY {table}_select ON {table} FOR SELECT
            USING (
                public.app_has_assessment_role(
                    assessment_id, workspace_id, NULL::text[]
                )
            );
            CREATE POLICY {table}_mutate ON {table} FOR ALL
            USING (
                public.app_has_assessment_role(
                    assessment_id,
                    workspace_id,
                    ARRAY['owner', 'analyst']::text[]
                )
            )
            WITH CHECK (
                public.app_has_assessment_role(
                    assessment_id,
                    workspace_id,
                    ARRAY['owner', 'analyst']::text[]
                )
            );
            """
        )

    op.execute(
        """
        CREATE POLICY job_attempt_select ON job_attempt FOR SELECT
        USING (public.app_has_job_role(job_id, NULL::text[]));
        CREATE POLICY job_attempt_mutate ON job_attempt FOR ALL
        USING (public.app_has_job_role(job_id, ARRAY['owner', 'analyst']::text[]))
        WITH CHECK (public.app_has_job_role(job_id, ARRAY['owner', 'analyst']::text[]));
        """
    )

    op.execute(
        """
        CREATE POLICY provider_quota_select ON provider_quota FOR SELECT
        USING (public.app_has_workspace_membership(workspace_id));
        CREATE POLICY provider_quota_mutate ON provider_quota FOR ALL
        USING (public.app_is_workspace_admin(workspace_id))
        WITH CHECK (public.app_is_workspace_admin(workspace_id));
        CREATE POLICY quota_reservation_select ON quota_reservation FOR SELECT
        USING (public.app_has_workspace_membership(workspace_id));
        CREATE POLICY quota_reservation_mutate ON quota_reservation FOR ALL
        USING (public.app_has_job_role(job_id, ARRAY['owner', 'analyst']::text[]))
        WITH CHECK (public.app_has_job_role(job_id, ARRAY['owner', 'analyst']::text[]));
        """
    )

    for table in (
        "host",
        "run_host",
        "ct_name_observation",
        "check_result",
        "finding",
    ):
        op.execute(
            f"""
            CREATE POLICY {table}_select ON {table} FOR SELECT
            USING (
                public.app_has_assessment_role(
                    assessment_id, workspace_id, NULL::text[]
                )
            );
            """
        )

    op.execute(
        """
        CREATE POLICY finding_annotation_select ON finding_annotation FOR SELECT
        USING (
            public.app_has_assessment_role(
                assessment_id, workspace_id, NULL::text[]
            )
        );
        CREATE POLICY finding_annotation_insert ON finding_annotation FOR INSERT
        WITH CHECK (
            public.app_has_assessment_role(
                assessment_id,
                workspace_id,
                ARRAY['owner', 'analyst', 'reviewer']::text[]
            )
            AND author_id = NULLIF(current_setting('app.user_id', true), '')::uuid
        );
        CREATE POLICY finding_annotation_update ON finding_annotation FOR UPDATE
        USING (
            author_id = NULLIF(current_setting('app.user_id', true), '')::uuid
            AND public.app_has_assessment_role(
                assessment_id,
                workspace_id,
                ARRAY['owner', 'analyst', 'reviewer']::text[]
            )
        )
        WITH CHECK (
            author_id = NULLIF(current_setting('app.user_id', true), '')::uuid
            AND public.app_has_assessment_role(
                assessment_id,
                workspace_id,
                ARRAY['owner', 'analyst', 'reviewer']::text[]
            )
        );
        CREATE POLICY finding_annotation_delete ON finding_annotation FOR DELETE
        USING (
            author_id = NULLIF(current_setting('app.user_id', true), '')::uuid
            AND public.app_has_assessment_role(
                assessment_id,
                workspace_id,
                ARRAY['owner', 'analyst', 'reviewer']::text[]
            )
        );
        """
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    _drop_existing_policies()
    _create_helpers()
    _create_identity_policies()
    _create_case_data_policies()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    # A security rollback fails closed.  Older migrations subsequently remove the tables
    # during a full downgrade; a direct downgrade to 0004 intentionally leaves RLS enabled
    # without permissive policies rather than restoring the recursive/broad policies.
    for table in CONTENT_TABLES:
        op.execute(
            f"""
            DO $drop_policies$
            DECLARE policy_name text;
            BEGIN
                FOR policy_name IN
                    SELECT pol.polname
                    FROM pg_catalog.pg_policy AS pol
                    JOIN pg_catalog.pg_class AS cls ON cls.oid = pol.polrelid
                    JOIN pg_catalog.pg_namespace AS ns ON ns.oid = cls.relnamespace
                    WHERE ns.nspname = 'public' AND cls.relname = '{table}'
                LOOP
                    EXECUTE format('DROP POLICY %I ON public.%I', policy_name, '{table}');
                END LOOP;
            END
            $drop_policies$;
            """
        )

    for signature in (
        "app_has_job_role(uuid, text[])",
        "app_can_manage_report_grant(uuid, uuid, uuid)",
        "app_can_manage_assessment_grant(uuid, uuid, uuid)",
        "app_has_report_version_access(uuid, uuid)",
        "app_has_assessment_role(uuid, uuid, text[])",
        "app_is_workspace_admin(uuid)",
        "app_has_workspace_membership(uuid)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS public.{signature}")
