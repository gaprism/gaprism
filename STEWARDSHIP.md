# Stewardship

What the maintainer promises to the people who use this tool and to those who contribute to it. The
code is licensed under the [Apache License 2.0](LICENSE) whatever this page says; this page is about
how the project is run and where its limits are.

## Who it is for, and where the line is

Web Due Diligence is built for the **analyst** who runs assessments of a domain and has to judge
what they find. Everything that serves that person is open source: the evidence engine, the rules
and findings, the exports and the printable report, accounts, sign-in with two steps, the audit
log, the command line and the translations.

A commercial edition may be offered next to it, built on this repository. It is meant for what the
analyst does not need but a larger organisation does: monitoring over time, portfolio and workflow
(reviews, approvals, regulatory content), single sign-on and administration, and hosting for many.
Where a new feature falls on this line is decided by who it serves, and **when in doubt it is
open**.

Pricing, the commercial edition's plans and its customers are not published here.

## What the maintainer commits to

1. **Nothing that shipped moves.** A feature that has shipped in the open edition never moves into
   a paid edition. New commercial features above the line are possible; moving released ones down
   is not.
2. **No artificial limits.** The open edition has no limit that exists to push you to the
   commercial one. The safety limits (hosts per run, scans per hour per person) stay configurable by
   whoever runs the installation.
3. **The licence stays.** Released components stay under the Apache License 2.0.
4. **Tests ship with the features** they test.
5. **Changes to the line are announced** with their reasons before the release that contains them.
6. **The open edition does not phone home.** It sends no telemetry, no crash reports and no update
   checks, and it checks no licence. Every outbound request goes to a scan target or to a data
   source that [docs/deploy.md](docs/deploy.md#what-leaves-your-network) lists, and the pages load
   nothing from outside the installation. Tests keep this true:
   [tests/test_outbound.py](tests/test_outbound.py) ties the list of destinations to the code and
   checks the pages and the Content-Security-Policy. A commercial edition that customers run
   themselves may carry licence terms of its own; they live in that package, never in this
   repository, and are disclosed to those customers.

Only the maintainer can make an exception to these commitments, in writing, and announces it
before the release that contains it.

## Contributing

Contributions are welcome under the rules in [CONTRIBUTING.md](CONTRIBUTING.md): the Apache License
2.0 in, the same out, and a sign-off under the Developer Certificate of Origin on every commit.

If you want to build a feature in one of the commercial categories above, open an issue first. It is
discussed before any code is written; if it is accepted and merged, it is open for good.

Regular contributors who review carefully and keep to the project's rules can be invited to become
maintainers; say so in an issue.

## Maintenance

The project is maintained by one person ([stalpers](https://github.com/stalpers)) alongside other
work, and there is no backup maintainer yet. That is why these commitments are small and specific:

- a release at least every quarter once there is a first release;
- a first reply to an issue or pull request within 7 days;
- an acknowledgement of a security report within 3 days ([SECURITY.md](SECURITY.md)).

If the maintainer can no longer look after the project, they hand the repository over to a new
maintainer and say so publicly before stepping back. Only if nobody can be found is it archived with
a notice, instead of going silent. The licence lets anyone carry on from a fork.

## What this page does not promise

Dates for features, a support contract, or that a commercial edition will or will not exist. For
questions about using the tool in an organisation, or about the commercial edition, see the contact
in the [README](README.md#contact).
