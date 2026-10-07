"""The ruleset of the technology check: what a technology looks like from outside.

A small, curated, own list: only signatures that are widely documented and specific enough not to
fire by accident (a header only that product sends, a cookie only it sets, a host only it serves
from). It is advisory by design: a technology that is not listed is simply not recognised, never
"not used", and a listed one may be hidden or spoofed. Each entry names the *evidence* kinds it
can be recognised by:

- ``headers``: (response header, regular expression on its value; empty = the header is present);
- ``cookies``: regular expressions matched at the start of a cookie name;
- ``generator``: regular expressions searched in ``<meta name="generator">``;
- ``hosts``: suffixes of the hosts the page loads scripts, styles, frames, images or forms from
  (``owns``: more hosts of the same vendor, only used to name the vendor of a third-party host);
- ``paths``: regular expressions searched in the path of any resource the page loads;
- ``markers``: interfaces that inline scripts call (``app/checks/page_facts.py``);
- ``networks``: names of the network hints of the IP check (``Cloudflare``, ``Fastly``, ...);
- ``cnames``: suffixes of the names in the host's CNAME chain.

``version`` regular expressions read a version from the evidence texts (header values, generator
text, ``path?ver=...``); ``implies`` names technologies that necessarily come with this one.

The categories say what a technology is. The *service* categories are the ones where another
organisation operates something that visitors' traffic or data reaches (a CDN, an analytics
service, a payment provider); they are what the "who processes it" card lists, and they are the
only ones whose vendor is named there. Software that the vendor runs itself (a web server, a CMS)
is not a service, even when it is popular.

Maintenance: add an entry only with evidence that is specific; the table-driven test in
``tests/checks/test_tech_check.py`` wants every entry to be recognised from at least one sample, and
a page without evidence to match nothing.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field

RULESET_DATE = "2026-10-07"  # when the entries and the end-of-life dates were last looked at

CATEGORIES: tuple[tuple[str, str], ...] = (
    ("edge", "CDN, proxy or WAF"),
    ("platform", "Hosting platform"),
    ("server", "Web server"),
    ("language", "Language or runtime"),
    ("framework", "Framework"),
    ("cms", "CMS or site generator"),
    ("ecommerce", "E-commerce"),
    ("js", "JavaScript library"),
    ("library_cdn", "Library CDN"),
    ("analytics", "Analytics"),
    ("tag_manager", "Tag manager"),
    ("advertising", "Advertising"),
    ("marketing", "Marketing and CRM"),
    ("support", "Chat and help desk"),
    ("payments", "Payments"),
    ("captcha", "Bot check"),
    ("consent", "Consent"),
    ("fonts", "Fonts and icons"),
    ("maps", "Maps"),
    ("video", "Video"),
    ("monitoring", "Monitoring"),
    ("social", "Social widgets"),
)
CATEGORY_ORDER = {key: number for number, (key, _name) in enumerate(CATEGORIES)}
# Another organisation operates something that visitors' traffic or data reaches.
SERVICE_CATEGORIES = frozenset(
    {
        "edge",
        "platform",
        "library_cdn",
        "analytics",
        "tag_manager",
        "advertising",
        "marketing",
        "support",
        "payments",
        "captcha",
        "consent",
        "fonts",
        "maps",
        "video",
        "monitoring",
        "social",
    }
)


@dataclass(frozen=True)
class Tech:
    key: str
    name: str
    category: str
    vendor: str | None = None  # who makes or operates it
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[str, ...] = ()
    generator: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    owns: tuple[str, ...] = ()  # hosts of this vendor that are not evidence for this entry
    paths: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    version: tuple[str, ...] = ()
    implies: tuple[str, ...] = ()
    service: bool | None = None  # default: by category
    self_hostable: bool = False  # a path or marker alone does not show a third party
    loose_paths: bool = False  # the paths are file names that other things may share: "medium"
    confidence: str = "high"  # "medium" where the evidence is common to a few products

    @property
    def is_service(self) -> bool:
        return self.category in SERVICE_CATEGORIES if self.service is None else self.service


_t = Tech  # entries below read better as ``_t(key, name, category, vendor, evidence...)``


_NUMBER = r"(\d+(?:\.\d+){0,3})"

TECHNOLOGIES: tuple[Tech, ...] = (
    # ----------------------------------------------------------------- CDN, proxy, WAF
    _t(
        "cloudflare",
        "Cloudflare",
        "edge",
        "Cloudflare",
        owns=("imagedelivery.net", "cloudflarestream.com"),
        headers=(("cf-ray", ""), ("server", r"^cloudflare"), ("cf-cache-status", "")),
        cookies=(r"__cf_bm$", r"cf_clearance$", r"__cfduid$", r"_cfuvid$"),
        networks=("Cloudflare",),
        cnames=("cdn.cloudflare.net", "cloudflare.net"),
    ),
    _t(
        "akamai",
        "Akamai",
        "edge",
        "Akamai",
        headers=(
            ("server", r"^akamai"),
            ("x-akamai-transformed", ""),
            ("x-akamai-request-id", ""),
            ("akamai-grn", ""),
        ),
        networks=("Akamai",),
        cnames=(
            "akamaiedge.net",
            "akamai.net",
            "edgekey.net",
            "edgesuite.net",
            "akamaitechnologies.com",
        ),
    ),
    _t(
        "akamai_bot_manager",
        "Akamai Bot Manager",
        "edge",
        "Akamai",
        cookies=(r"_abck$", r"ak_bmsc$", r"bm_sz$", r"bm_sv$"),
    ),
    _t(
        "fastly",
        "Fastly",
        "edge",
        "Fastly",
        headers=(
            ("x-served-by", r"^cache-"),
            ("fastly-debug-digest", ""),
            ("x-fastly-request-id", ""),
        ),
        networks=("Fastly",),
        cnames=("fastly.net", "fastlylb.net"),
    ),
    _t(
        "cloudfront",
        "Amazon CloudFront",
        "edge",
        "Amazon",
        headers=(
            ("x-amz-cf-id", ""),
            ("x-amz-cf-pop", ""),
            ("via", r"cloudfront"),
            ("server", r"^cloudfront"),
        ),
        networks=("Amazon CloudFront",),
        cnames=("cloudfront.net",),
    ),
    _t(
        "azure_front_door",
        "Azure Front Door / CDN",
        "edge",
        "Microsoft",
        headers=(("x-azure-ref", ""), ("x-msedge-ref", "")),
        networks=("Azure CDN / Front Door",),
        cnames=("azureedge.net", "azurefd.net"),
    ),
    _t(
        "imperva",
        "Imperva",
        "edge",
        "Imperva",
        headers=(("x-iinfo", ""), ("x-cdn", r"imperva|incapsula")),
        cookies=(r"visid_incap_", r"incap_ses_", r"nlbi_"),
        networks=("Imperva",),
        cnames=("incapdns.net",),
    ),
    _t(
        "sucuri",
        "Sucuri",
        "edge",
        "Sucuri",
        headers=(("x-sucuri-id", ""), ("x-sucuri-cache", ""), ("server", r"^sucuri")),
        networks=("Sucuri",),
        cnames=("sucuri.net",),
    ),
    _t(
        "stackpath",
        "StackPath",
        "edge",
        "StackPath",
        networks=("StackPath",),
        cnames=("stackpathdns.com",),
    ),
    _t(
        "bunny",
        "Bunny CDN",
        "edge",
        "Bunny.net",
        headers=(("server", r"^bunnycdn"), ("cdn-pullzone", "")),
        networks=("Bunny CDN",),
        cnames=("b-cdn.net",),
    ),
    _t("keycdn", "KeyCDN", "edge", "KeyCDN", headers=(("server", r"^keycdn"),)),
    _t(
        "cdn77",
        "CDN77",
        "edge",
        "CDN77",
        headers=(("server", r"^cdn77"),),
        networks=("CDN77",),
        cnames=("cdn77.org",),
    ),
    _t(
        "edgio",
        "Edgio (Edgecast, Limelight)",
        "edge",
        "Edgio",
        headers=(("server", r"^ecacc|^ecs |^ecd "),),
        networks=("Edgio (Edgecast, Limelight)",),
        cnames=("edgecastcdn.net", "llnwd.net"),
    ),
    _t("gcore", "Gcore", "edge", "Gcore", networks=("Gcore",), cnames=("gcdn.co",)),
    _t(
        "cdnetworks",
        "CDNetworks",
        "edge",
        "CDNetworks",
        networks=("CDNetworks",),
        cnames=("cdngc.net",),
    ),
    _t(
        "aws_elb",
        "AWS Elastic Load Balancing",
        "edge",
        "Amazon",
        headers=(("server", r"^awselb"),),
        cookies=(r"awsalb", r"awselb$"),
    ),
    _t(
        "f5_bigip",
        "F5 BIG-IP",
        "edge",
        "F5",
        headers=(("server", r"^big-?ip"),),
        cookies=(r"bigipserver", r"ts[0-9a-f]{8}$"),
    ),
    _t(
        "citrix_netscaler",
        "Citrix NetScaler",
        "edge",
        "Citrix",
        headers=(("via", r"^ns-cache"),),
        cookies=(r"nsc_", r"ns_af$"),
    ),
    _t("fortiweb", "Fortinet FortiWeb", "edge", "Fortinet", cookies=(r"fortiwafsid$",)),
    _t(
        "datadome",
        "DataDome",
        "edge",
        "DataDome",
        headers=(("x-datadome", ""), ("server", r"^datadome")),
        cookies=(r"datadome$",),
        hosts=("js.datadome.co", "api-js.datadome.co"),
    ),
    _t(
        "human_security",
        "HUMAN Security (PerimeterX)",
        "edge",
        "HUMAN Security",
        cookies=(r"_px[0-9a-z]*$", r"_pxhd$"),
        hosts=("client.perimeterx.net", "perimeterx.net", "px-cdn.net", "px-cloud.net"),
    ),
    # ----------------------------------------------------------------- hosting platforms
    _t(
        "vercel",
        "Vercel",
        "platform",
        "Vercel",
        headers=(("server", r"^vercel$"), ("x-vercel-id", ""), ("x-vercel-cache", "")),
        cnames=("vercel.app", "vercel-dns.com"),
    ),
    _t(
        "netlify",
        "Netlify",
        "platform",
        "Netlify",
        headers=(("server", r"^netlify"), ("x-nf-request-id", "")),
        cnames=("netlify.app", "netlify.com"),
    ),
    _t(
        "github",
        "GitHub",
        "platform",
        "GitHub",
        headers=(("x-github-request-id", ""),),
        owns=("githubassets.com", "githubusercontent.com"),
        cnames=("github.io",),
    ),
    _t(
        "heroku",
        "Heroku",
        "platform",
        "Salesforce",
        headers=(("via", r"vegur"),),
        cnames=("herokuapp.com", "herokudns.com"),
    ),
    _t(
        "google_frontend",
        "Google Cloud front end",
        "platform",
        "Google",
        headers=(
            ("server", r"^google frontend"),
            ("via", r"^1\.1 google"),
            ("x-cloud-trace-context", ""),
        ),
    ),
    _t(
        "azure_app_service",
        "Microsoft Azure App Service",
        "platform",
        "Microsoft",
        cookies=(r"arraffinity", r"arraffinitysamesite"),
        cnames=("azurewebsites.net",),
    ),
    _t(
        "amazon_s3",
        "Amazon S3",
        "platform",
        "Amazon",
        headers=(("server", r"^amazons3"), ("x-amz-request-id", "")),
        cnames=("s3.amazonaws.com",),
    ),
    _t(
        "wix",
        "Wix",
        "platform",
        "Wix",
        headers=(("x-wix-request-id", ""), ("server", r"^pepyaka")),
        generator=(r"^wix\.com",),
        hosts=(
            "static.parastorage.com",
            "parastorage.com",
            "wixstatic.com",
            "static.wixstatic.com",
        ),
        markers=("wixBiSession",),
    ),
    _t(
        "squarespace",
        "Squarespace",
        "platform",
        "Squarespace",
        headers=(("server", r"^squarespace"),),
        cookies=(r"ss_cvr$", r"ss_cvt$"),
        generator=(r"^squarespace",),
        hosts=("static1.squarespace.com", "images.squarespace-cdn.com", "sqspcdn.com"),
    ),
    _t(
        "webflow",
        "Webflow",
        "platform",
        "Webflow",
        generator=(r"^webflow",),
        hosts=("assets.website-files.com", "cdn.prod.website-files.com", "uploads-ssl.webflow.com"),
    ),
    # ----------------------------------------------------------------- web servers
    _t(
        "nginx",
        "nginx",
        "server",
        None,
        headers=(("server", r"^nginx"),),
        version=(r"nginx/" + _NUMBER,),
    ),
    _t(
        "apache",
        "Apache HTTP Server",
        "server",
        "Apache",
        headers=(("server", r"^apache(?!-coyote)"),),
        version=(r"apache/" + _NUMBER,),
    ),
    _t(
        "iis",
        "Microsoft IIS",
        "server",
        "Microsoft",
        headers=(("server", r"^microsoft-iis"),),
        version=(r"microsoft-iis/" + _NUMBER,),
    ),
    _t(
        "litespeed",
        "LiteSpeed",
        "server",
        "LiteSpeed Technologies",
        headers=(
            ("server", r"^litespeed"),
            ("x-litespeed-cache", ""),
            ("x-turbo-charged-by", r"litespeed"),
        ),
    ),
    _t(
        "openresty",
        "OpenResty",
        "server",
        None,
        headers=(("server", r"^openresty"),),
        version=(r"openresty/" + _NUMBER,),
    ),
    _t("caddy", "Caddy", "server", None, headers=(("server", r"^caddy"),)),
    _t("envoy", "Envoy", "server", None, headers=(("server", r"^envoy"),)),
    _t(
        "tomcat",
        "Apache Tomcat (Coyote)",
        "server",
        "Apache",
        headers=(("server", r"^apache-coyote"),),
        implies=("java",),
    ),
    _t(
        "jetty",
        "Jetty",
        "server",
        "Eclipse",
        headers=(("server", r"^jetty"),),
        version=(r"jetty\(" + _NUMBER,),
        implies=("java",),
    ),
    _t(
        "kestrel",
        "Kestrel (ASP.NET Core)",
        "server",
        "Microsoft",
        headers=(("server", r"^kestrel"),),
        implies=("aspnet",),
    ),
    _t(
        "gunicorn",
        "Gunicorn",
        "server",
        None,
        headers=(("server", r"^gunicorn"),),
        version=(r"gunicorn/" + _NUMBER,),
        implies=("python",),
    ),
    _t(
        "lighttpd",
        "lighttpd",
        "server",
        None,
        headers=(("server", r"^lighttpd"),),
        version=(r"lighttpd/" + _NUMBER,),
    ),
    _t("varnish", "Varnish", "server", None, headers=(("x-varnish", ""), ("via", r"varnish"))),
    # ----------------------------------------------------------------- languages, runtimes
    _t(
        "php",
        "PHP",
        "language",
        "PHP Group",
        headers=(("x-powered-by", r"^php"),),
        cookies=(r"phpsessid$",),
        version=(r"php/" + _NUMBER,),
    ),
    _t(
        "aspnet",
        "ASP.NET",
        "language",
        "Microsoft",
        headers=(("x-powered-by", r"^asp\.net"), ("x-aspnet-version", "")),
        cookies=(r"asp\.net_sessionid$", r"\.aspxauth$", r"__requestverificationtoken"),
        version=(r"^x-aspnet-version: " + _NUMBER,),
    ),
    _t(
        "java",
        "Java (servlet container)",
        "language",
        "Oracle",
        headers=(("x-powered-by", r"servlet|jsp|jboss|weblogic|websphere|glassfish"),),
        cookies=(r"jsessionid$",),
    ),
    _t(
        "python",
        "Python",
        "language",
        "Python Software Foundation",
        headers=(("server", r"python|werkzeug"),),
        version=(r"(?:cpython|python)/" + _NUMBER,),
    ),
    _t(
        "ruby",
        "Ruby (Rack, Rails)",
        "language",
        None,
        headers=(("x-runtime", r"^\d+\.\d+$"),),
        confidence="medium",
    ),
    _t("nodejs", "Node.js", "language", "OpenJS Foundation"),
    # ----------------------------------------------------------------- frameworks
    _t(
        "express",
        "Express",
        "framework",
        None,
        headers=(("x-powered-by", r"^express"),),
        implies=("nodejs",),
    ),
    _t(
        "nextjs",
        "Next.js",
        "framework",
        "Vercel",
        headers=(
            ("x-powered-by", r"^next\.js"),
            ("x-nextjs-cache", ""),
            ("x-nextjs-matched-path", ""),
        ),
        paths=(r"^/_next/(?:static|image)",),
        version=(r"next\.js[ /]" + _NUMBER,),
        implies=("react", "nodejs"),
    ),
    _t(
        "nuxt",
        "Nuxt",
        "framework",
        None,
        headers=(("x-powered-by", r"^nuxt"),),
        paths=(r"^/_nuxt/",),
        implies=("vue",),
    ),
    _t(
        "gatsby",
        "Gatsby",
        "framework",
        None,
        generator=(r"^gatsby",),
        headers=(("x-powered-by", r"^gatsby"),),
        implies=("react",),
    ),
    _t("laravel", "Laravel", "framework", None, cookies=(r"laravel_session$",), implies=("php",)),
    _t(
        "django",
        "Django",
        "framework",
        None,
        cookies=(r"csrftoken$",),
        implies=("python",),
        confidence="medium",
    ),
    _t(
        "symfony",
        "Symfony",
        "framework",
        None,
        headers=(("x-debug-token", ""),),
        cookies=(r"sf_redirect$",),
        implies=("php",),
    ),
    _t(
        "spring",
        "Spring",
        "framework",
        None,
        headers=(("x-application-context", ""),),
        implies=("java",),
    ),
    _t(
        "aspnet_mvc",
        "ASP.NET MVC",
        "framework",
        "Microsoft",
        headers=(("x-aspnetmvc-version", ""),),
        implies=("aspnet",),
    ),
    # ----------------------------------------------------------------- CMS and site generators
    _t(
        "wordpress",
        "WordPress",
        "cms",
        "WordPress",
        owns=("w.org", "wp.com"),  # WordPress.org's static files, Automattic's services (Jetpack)
        headers=(("link", r"api\.w\.org"), ("x-pingback", ""), ("x-redirect-by", r"^wordpress")),
        cookies=(r"wordpress_", r"wp-settings-", r"wordpress_test_cookie$"),
        generator=(r"^wordpress",),
        paths=(r"/wp-(?:content|includes)/", r"/wp-json/"),
        version=(
            r"wordpress[ /]?" + _NUMBER,
            r"wp-emoji-release\.min\.js\?ver=" + _NUMBER,
            r"wp-embed\.min\.js\?ver=" + _NUMBER,
            r"wp-includes/css/(?:dist/block-library/style|classic-themes|dashicons)\.min\.css\?ver="
            + _NUMBER,
        ),
        implies=("php",),
    ),
    _t(
        "woocommerce",
        "WooCommerce",
        "ecommerce",
        "Automattic",
        generator=(r"^woocommerce",),
        cookies=(r"woocommerce_", r"wp_woocommerce_session_"),
        paths=(r"/wp-content/plugins/woocommerce/",),
        version=(r"woocommerce[ /]" + _NUMBER, r"plugins/woocommerce/[^?]*\?ver=" + _NUMBER),
        implies=("wordpress",),
    ),
    _t(
        "elementor",
        "Elementor",
        "cms",
        "Elementor",
        generator=(r"^elementor",),
        paths=(r"/wp-content/plugins/elementor/",),
        version=(r"elementor[ /]" + _NUMBER,),
        implies=("wordpress",),
    ),
    _t(
        "drupal",
        "Drupal",
        "cms",
        "Drupal Association",
        headers=(
            ("x-generator", r"^drupal"),
            ("x-drupal-cache", ""),
            ("x-drupal-dynamic-cache", ""),
        ),
        generator=(r"^drupal",),
        paths=(
            r"/sites/(?:default|all)/(?:files|modules|themes)/",
            r"^/core/(?:misc|assets)/",
            r"^/misc/drupal\.js",
        ),
        version=(r"drupal " + _NUMBER,),
        implies=("php",),
    ),
    _t(
        "joomla",
        "Joomla",
        "cms",
        "Open Source Matters",
        headers=(("x-content-encoded-by", r"^joomla"),),
        generator=(r"^joomla",),
        paths=(r"^/media/system/js/", r"/components/com_"),
        version=(r"joomla! " + _NUMBER,),
        implies=("php",),
    ),
    _t(
        "typo3",
        "TYPO3",
        "cms",
        "TYPO3 Association",
        generator=(r"^typo3",),
        paths=(r"/typo3(?:conf|temp)/",),
        version=(r"typo3 " + _NUMBER,),
        implies=("php",),
    ),
    _t(
        "ghost",
        "Ghost",
        "cms",
        "Ghost Foundation",
        headers=(("x-ghost-cache-status", ""),),
        generator=(r"^ghost",),
        version=(r"ghost " + _NUMBER,),
    ),
    _t("hugo", "Hugo", "cms", None, generator=(r"^hugo",), version=(r"hugo " + _NUMBER,)),
    _t("jekyll", "Jekyll", "cms", None, generator=(r"^jekyll",), version=(r"jekyll v?" + _NUMBER,)),
    _t(
        "docusaurus",
        "Docusaurus",
        "cms",
        "Meta",
        generator=(r"^docusaurus",),
        version=(r"docusaurus v?" + _NUMBER,),
        implies=("react",),
    ),
    _t(
        "umbraco",
        "Umbraco",
        "cms",
        "Umbraco",
        generator=(r"^umbraco",),
        paths=(r"^/umbraco/",),
        implies=("aspnet",),
    ),
    _t(
        "aem",
        "Adobe Experience Manager",
        "cms",
        "Adobe",
        paths=(r"^/etc\.clientlibs/", r"^/etc/designs/", r"^/libs/granite/"),
        implies=("java",),
    ),
    _t(
        "magento",
        "Magento (Adobe Commerce)",
        "ecommerce",
        "Adobe",
        headers=(("x-magento-cache-debug", ""), ("x-magento-tags", "")),
        cookies=(r"mage-cache-", r"mage-messages$"),
        paths=(r"^/static/version\d+/", r"^/mage/"),
        implies=("php",),
    ),
    _t(
        "prestashop",
        "PrestaShop",
        "ecommerce",
        "PrestaShop",
        generator=(r"^prestashop",),
        cookies=(r"prestashop-[0-9a-f]{32}",),
        implies=("php",),
    ),
    _t(
        "shopware",
        "Shopware",
        "ecommerce",
        "Shopware",
        paths=(r"^/bundles/storefront/",),
        implies=("php",),
    ),
    _t(
        "shopify",
        "Shopify",
        "ecommerce",
        "Shopify",
        headers=(("x-shopid", ""), ("x-sorting-hat-shopid", ""), ("x-shopify-stage", "")),
        cookies=(r"_shopify_[a-z]", r"secure_customer_sig$"),
        hosts=("cdn.shopify.com", "cdn.shopifycdn.net", "myshopify.com"),
        markers=("Shopify",),
        paths=(r"^/cdn/shop/",),
        cnames=("myshopify.com",),
        service=True,
    ),
    _t(
        "bigcommerce",
        "BigCommerce",
        "ecommerce",
        "BigCommerce",
        hosts=("cdn11.bigcommerce.com", "bigcommerce.com"),
        service=True,
    ),
    # ----------------------------------------------------------------- JavaScript libraries
    _t(
        "jquery",
        "jQuery",
        "js",
        "OpenJS Foundation",
        paths=(r"jquery(?:[-.]\d+\.\d+(?:\.\d+)?)?(?:\.slim)?(?:\.min)?\.js$",),
        version=(
            r"jquery[-.]" + _NUMBER,
            r"jquery(?:\.min)?\.js\?ver=" + _NUMBER,
            r"jquery/" + _NUMBER,
        ),
        loose_paths=True,
    ),
    _t(
        "jquery_ui",
        "jQuery UI",
        "js",
        "OpenJS Foundation",
        paths=(r"jquery-ui(?:[-.]\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js$",),
        version=(r"jquery-ui[-.]" + _NUMBER, r"jqueryui/" + _NUMBER),
        loose_paths=True,
    ),
    _t(
        "bootstrap",
        "Bootstrap",
        "js",
        "Bootstrap",
        paths=(r"bootstrap(?:[-.]\d+\.\d+(?:\.\d+)?)?(?:\.bundle)?(?:\.min)?\.(?:js|css)$",),
        version=(r"bootstrap[@/-]v?" + _NUMBER, r"bootstrap/" + _NUMBER),
        loose_paths=True,
    ),
    _t(
        "angularjs",
        "AngularJS",
        "js",
        "Google",
        paths=(r"angular(?:js)?(?:\.min)?\.js$",),
        version=(r"angular(?:js)?[/@.-]v?(1\.\d+\.\d+)", r"angularjs/(1\.\d+\.\d+)"),
        loose_paths=True,
    ),
    _t(
        "react",
        "React",
        "js",
        "Meta",
        paths=(r"react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js$",),
        version=(r"react(?:-dom)?[@/]v?" + _NUMBER,),
        loose_paths=True,
    ),
    _t(
        "vue",
        "Vue.js",
        "js",
        None,
        paths=(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js$",),
        version=(r"vue[@/]v?" + _NUMBER,),
        loose_paths=True,
    ),
    # ----------------------------------------------------------------- library CDNs
    _t("cdnjs", "cdnjs", "library_cdn", "Cloudflare", hosts=("cdnjs.cloudflare.com",)),
    _t(
        "jsdelivr",
        "jsDelivr",
        "library_cdn",
        "jsDelivr",
        hosts=("cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net"),
    ),
    _t("unpkg", "unpkg", "library_cdn", "unpkg", hosts=("unpkg.com",)),
    _t(
        "google_hosted_libraries",
        "Google Hosted Libraries",
        "library_cdn",
        "Google",
        hosts=("ajax.googleapis.com",),
    ),
    _t("jquery_cdn", "jQuery CDN", "library_cdn", "OpenJS Foundation", hosts=("code.jquery.com",)),
    _t(
        "bootstrapcdn",
        "BootstrapCDN",
        "library_cdn",
        "jsDelivr",
        hosts=("maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com", "netdna.bootstrapcdn.com"),
    ),
    _t(
        "microsoft_ajax_cdn",
        "Microsoft Ajax CDN",
        "library_cdn",
        "Microsoft",
        hosts=("ajax.aspnetcdn.com", "ajax.microsoft.com"),
    ),
    _t(
        "polyfill_io", "polyfill.io", "library_cdn", "Funnull", hosts=("polyfill.io",)
    ),  # since 2024
    _t(
        "bootcdn",
        "BootCDN and similar",
        "library_cdn",
        None,
        hosts=("bootcss.com", "bootcdn.net", "staticfile.org", "staticfile.net"),
    ),
    # ----------------------------------------------------------------- analytics and tags
    _t(
        "google_analytics",
        "Google Analytics (gtag.js)",
        "analytics",
        "Google",
        hosts=("google-analytics.com", "analytics.google.com"),
        paths=(r"^/gtag/js$",),
        markers=("gtag", "ga", "_gaq"),
    ),
    _t(
        "google_tag_manager",
        "Google Tag Manager",
        "tag_manager",
        "Google",
        paths=(r"^/(?:gtm\.js|ns\.html)$",),
        markers=("gtm",),
        owns=("googletagmanager.com",),  # gtag.js comes from there too: not evidence for this one
    ),
    _t(
        "hotjar",
        "Hotjar",
        "analytics",
        "Hotjar",
        hosts=("static.hotjar.com", "script.hotjar.com", "insights.hotjar.com"),
        markers=("hj",),
    ),
    _t(
        "clarity",
        "Microsoft Clarity",
        "analytics",
        "Microsoft",
        hosts=("clarity.ms",),
        markers=("clarity",),
    ),
    _t(
        "matomo",
        "Matomo",
        "analytics",
        "Matomo",
        hosts=("cdn.matomo.cloud", "matomo.cloud"),
        paths=(r"(?:^|/)(?:matomo|piwik)\.js$", r"/(?:matomo|piwik)\.php$"),
        markers=("_paq",),
        self_hostable=True,
    ),
    _t(
        "plausible",
        "Plausible",
        "analytics",
        "Plausible",
        hosts=("plausible.io",),
        paths=(r"/js/plausible[\w.\-]*\.js$",),  # not script.js: any site may call a file that
        self_hostable=True,
    ),
    _t("fathom", "Fathom", "analytics", "Fathom Analytics", hosts=("cdn.usefathom.com",)),
    _t(
        "segment",
        "Segment",
        "analytics",
        "Twilio",
        hosts=("cdn.segment.com", "cdn.segment.io"),
        markers=("analytics",),
        confidence="medium",
    ),
    _t(
        "mixpanel",
        "Mixpanel",
        "analytics",
        "Mixpanel",
        hosts=("cdn.mxpnl.com", "cdn.mixpanel.com"),
        markers=("mixpanel",),
    ),
    _t(
        "adobe_analytics",
        "Adobe Analytics and Launch",
        "analytics",
        "Adobe",
        hosts=("assets.adobedtm.com", "omtrdc.net", "demdex.net", "2o7.net"),
    ),
    _t(
        "cloudflare_web_analytics",
        "Cloudflare Web Analytics",
        "analytics",
        "Cloudflare",
        hosts=("cloudflareinsights.com",),
    ),
    _t(
        "optimizely",
        "Optimizely",
        "analytics",
        "Optimizely",
        hosts=("cdn.optimizely.com", "logx.optimizely.com"),
    ),
    # ----------------------------------------------------------------- advertising
    _t(
        "google_ads",
        "Google Ads",
        "advertising",
        "Google",
        hosts=("googleadservices.com", "googlesyndication.com", "doubleclick.net"),
    ),
    _t(
        "meta_pixel",
        "Meta Pixel",
        "advertising",
        "Meta",
        paths=(r"/fbevents\.js$",),
        markers=("fbq",),
    ),
    _t(
        "linkedin_insight",
        "LinkedIn Insight Tag",
        "advertising",
        "Microsoft",
        hosts=("snap.licdn.com", "px.ads.linkedin.com"),
        markers=("lintrk",),
    ),
    _t(
        "tiktok_pixel",
        "TikTok Pixel",
        "advertising",
        "ByteDance",
        hosts=("analytics.tiktok.com",),
        markers=("ttq",),
    ),
    _t(
        "twitter_pixel",
        "X (Twitter) ads",
        "advertising",
        "X Corp.",
        hosts=("static.ads-twitter.com", "analytics.twitter.com"),
        markers=("twq",),
    ),
    _t(
        "pinterest_tag",
        "Pinterest Tag",
        "advertising",
        "Pinterest",
        hosts=("ct.pinterest.com",),
        paths=(r"^/ct/core\.js$",),
    ),
    _t(
        "criteo",
        "Criteo",
        "advertising",
        "Criteo",
        hosts=("static.criteo.net", "dis.criteo.com", "widget.criteo.com"),
    ),
    _t(
        "taboola", "Taboola", "advertising", "Taboola", hosts=("cdn.taboola.com", "trc.taboola.com")
    ),
    _t(
        "outbrain",
        "Outbrain",
        "advertising",
        "Outbrain",
        hosts=("widgets.outbrain.com", "amplify.outbrain.com"),
    ),
    _t("carbon_ads", "Carbon Ads", "advertising", "BuySellAds", hosts=("cdn.carbonads.com",)),
    # ----------------------------------------------------------------- marketing, support, forms
    _t(
        "hubspot",
        "HubSpot",
        "marketing",
        "HubSpot",
        hosts=(
            "js.hs-scripts.com",
            "js.hs-analytics.net",
            "js.hsforms.net",
            "js.hscollectedforms.net",
            "forms.hsforms.com",
            "js.usemessages.com",
        ),
    ),
    _t(
        "marketo",
        "Marketo",
        "marketing",
        "Adobe",
        hosts=("munchkin.marketo.net", "munchkin.marketo.com"),
    ),
    _t("pardot", "Pardot", "marketing", "Salesforce", hosts=("pi.pardot.com", "cdn.pardot.com")),
    _t(
        "mailchimp",
        "Mailchimp",
        "marketing",
        "Intuit",
        hosts=("chimpstatic.com", "list-manage.com"),
    ),
    _t("klaviyo", "Klaviyo", "marketing", "Klaviyo", hosts=("static.klaviyo.com", "a.klaviyo.com")),
    _t("typeform", "Typeform", "marketing", "Typeform", hosts=("embed.typeform.com",)),
    _t(
        "calendly",
        "Calendly",
        "marketing",
        "Calendly",
        hosts=("assets.calendly.com", "calendly.com"),
    ),
    _t(
        "intercom",
        "Intercom",
        "support",
        "Intercom",
        hosts=("widget.intercom.io", "js.intercomcdn.com", "api-iam.intercom.io"),
        markers=("Intercom",),
    ),
    _t("drift", "Drift", "support", "Salesloft", hosts=("js.driftt.com",), markers=("drift",)),
    _t(
        "zendesk",
        "Zendesk",
        "support",
        "Zendesk",
        hosts=("static.zdassets.com", "ekr.zdassets.com"),
    ),
    _t(
        "freshworks",
        "Freshworks (Freshchat, Freshdesk)",
        "support",
        "Freshworks",
        hosts=("wchat.freshchat.com", "widget.freshworks.com"),
    ),
    _t("livechat", "LiveChat", "support", "LiveChat", hosts=("cdn.livechatinc.com",)),
    _t("tawk", "Tawk.to", "support", "Tawk.to", hosts=("embed.tawk.to",)),
    _t("crisp", "Crisp", "support", "Crisp", hosts=("client.crisp.chat",)),
    _t(
        "helpscout",
        "Help Scout Beacon",
        "support",
        "Help Scout",
        hosts=("beacon-v2.helpscout.net",),
    ),
    # ----------------------------------------------------------------- payments
    _t(
        "stripe",
        "Stripe",
        "payments",
        "Stripe",
        hosts=("js.stripe.com", "m.stripe.network", "checkout.stripe.com"),
    ),
    _t(
        "paypal",
        "PayPal",
        "payments",
        "PayPal",
        hosts=("paypalobjects.com",),
        paths=(r"^/sdk/js$",),
    ),
    _t(
        "adyen",
        "Adyen",
        "payments",
        "Adyen",
        hosts=("checkoutshopper-live.adyen.com", "checkoutshopper-test.adyen.com"),
    ),
    _t(
        "braintree",
        "Braintree",
        "payments",
        "PayPal",
        hosts=("js.braintreegateway.com", "assets.braintreegateway.com"),
    ),
    _t("square", "Square", "payments", "Block", hosts=("js.squareup.com", "web.squarecdn.com")),
    _t("klarna", "Klarna", "payments", "Klarna", hosts=("x.klarnacdn.net", "js.klarna.com")),
    _t("mollie", "Mollie", "payments", "Mollie", hosts=("js.mollie.com",)),
    _t("datatrans", "Datatrans", "payments", "Datatrans", hosts=("pay.datatrans.com",)),
    # ----------------------------------------------------------------- bot checks, consent
    _t(
        "recaptcha",
        "Google reCAPTCHA",
        "captcha",
        "Google",
        hosts=("recaptcha.net",),
        owns=("www.google.com", "www.gstatic.com"),  # serve it too, but are not evidence for it
        paths=(r"^/recaptcha/",),
    ),
    _t("hcaptcha", "hCaptcha", "captcha", "Intuition Machines", hosts=("hcaptcha.com",)),
    _t(
        "turnstile",
        "Cloudflare Turnstile",
        "captcha",
        "Cloudflare",
        hosts=("challenges.cloudflare.com",),
    ),
    _t(
        "cookiebot",
        "Cookiebot",
        "consent",
        "Usercentrics",
        hosts=("consent.cookiebot.com", "consentcdn.cookiebot.com"),
    ),
    _t(
        "onetrust",
        "OneTrust",
        "consent",
        "OneTrust",
        hosts=("cdn.cookielaw.org", "cookielaw.org", "onetrust.com"),
    ),
    _t(
        "usercentrics",
        "Usercentrics",
        "consent",
        "Usercentrics",
        hosts=("app.usercentrics.eu", "usercentrics.eu"),
    ),
    _t("didomi", "Didomi", "consent", "Didomi", hosts=("sdk.privacy-center.org",)),
    _t("iubenda", "iubenda", "consent", "iubenda", hosts=("cdn.iubenda.com", "iubenda.com")),
    _t("termly", "Termly", "consent", "Termly", hosts=("app.termly.io",)),
    _t("cookieyes", "CookieYes", "consent", "CookieYes", hosts=("cdn-cookieyes.com",)),
    _t("trustarc", "TrustArc", "consent", "TrustArc", hosts=("consent.trustarc.com",)),
    # ----------------------------------------------------------------- fonts, maps, video
    _t(
        "google_fonts",
        "Google Fonts",
        "fonts",
        "Google",
        hosts=("fonts.googleapis.com", "fonts.gstatic.com"),
    ),
    _t("adobe_fonts", "Adobe Fonts", "fonts", "Adobe", hosts=("use.typekit.net", "p.typekit.net")),
    _t(
        "fontawesome",
        "Font Awesome",
        "fonts",
        "Fonticons",
        hosts=("use.fontawesome.com", "kit.fontawesome.com"),
    ),
    _t("bunny_fonts", "Bunny Fonts", "fonts", "Bunny.net", hosts=("fonts.bunny.net",)),
    _t(
        "google_maps",
        "Google Maps",
        "maps",
        "Google",
        hosts=("maps.googleapis.com", "maps.gstatic.com"),
        paths=(r"^/maps/(?:embed|api)",),
    ),
    _t("mapbox", "Mapbox", "maps", "Mapbox", hosts=("api.mapbox.com", "events.mapbox.com")),
    _t(
        "openstreetmap",
        "OpenStreetMap",
        "maps",
        "OpenStreetMap Foundation",
        hosts=("tile.openstreetmap.org", "openstreetmap.org"),
    ),
    _t("swisstopo", "swisstopo (geo.admin.ch)", "maps", "swisstopo", hosts=("geo.admin.ch",)),
    _t(
        "youtube",
        "YouTube",
        "video",
        "Google",
        hosts=("youtube.com", "youtube-nocookie.com", "ytimg.com"),
    ),
    _t("vimeo", "Vimeo", "video", "Vimeo", hosts=("player.vimeo.com", "vimeocdn.com")),
    _t(
        "wistia",
        "Wistia",
        "video",
        "Wistia",
        hosts=("fast.wistia.com", "fast.wistia.net", "embed.wistia.com"),
    ),
    _t("brightcove", "Brightcove", "video", "Brightcove", hosts=("players.brightcove.net",)),
    # ----------------------------------------------------------------- monitoring, social
    _t(
        "sentry",
        "Sentry",
        "monitoring",
        "Sentry",
        hosts=("browser.sentry-cdn.com", "js.sentry-cdn.com"),
        markers=("Sentry",),
    ),
    _t(
        "datadog_rum",
        "Datadog RUM",
        "monitoring",
        "Datadog",
        hosts=("datadoghq-browser-agent.com",),
    ),
    _t(
        "newrelic",
        "New Relic",
        "monitoring",
        "New Relic",
        hosts=("js-agent.newrelic.com", "bam.nr-data.net", "bam-cell.nr-data.net"),
    ),
    _t(
        "logrocket",
        "LogRocket",
        "monitoring",
        "LogRocket",
        hosts=("cdn.logrocket.io", "cdn.lr-ingest.io", "cdn.lr-in.com"),
    ),
    _t(
        "facebook_sdk",
        "Facebook SDK",
        "social",
        "Meta",
        paths=(r"^/[a-z]{2}_[A-Z]{2}/(?:sdk|all)\.js$",),
    ),
    _t(
        "twitter_widgets",
        "X (Twitter) widgets",
        "social",
        "X Corp.",
        hosts=("platform.twitter.com", "platform.x.com", "syndication.twitter.com"),
    ),
    _t(
        "instagram_embed",
        "Instagram embeds",
        "social",
        "Meta",
        hosts=("instagram.com",),
        paths=(r"^/embed\.js$",),
    ),
    _t(
        "linkedin_widgets",
        "LinkedIn widgets",
        "social",
        "Microsoft",
        hosts=("platform.linkedin.com",),
    ),
    _t("addthis", "AddThis", "social", "Oracle", hosts=("s7.addthis.com", "m.addthis.com")),
    _t(
        "sharethis",
        "ShareThis",
        "social",
        "ShareThis",
        hosts=("platform-api.sharethis.com", "w.sharethis.com"),
    ),
)

BY_KEY = {tech.key: tech for tech in TECHNOLOGIES}

# Hosts that served or still serve malicious code to the visitors of the pages that load from
# them. A page that loads a script from one of them hands its visitors to whoever controls it.
FLAGGED_HOSTS: dict[str, str] = {
    "polyfill.io": "supply_chain_2024",  # sold in February 2024; served malware from June 2024
    "bootcss.com": "supply_chain_2024",
    "bootcdn.net": "supply_chain_2024",
    "staticfile.org": "supply_chain_2024",
    "staticfile.net": "supply_chain_2024",
    "unionadjs.com": "supply_chain_2024",
    "xhsbpza.com": "supply_chain_2024",
    "union.macoms.la": "supply_chain_2024",
    "newcrbpc.com": "supply_chain_2024",
}


# ----------------------------------------------------------------------------- old versions


@dataclass(frozen=True)
class Old:
    """A version range that is past its upstream end of life or has well-known vulnerabilities."""

    below: tuple[int, ...]  # the versions before this one (exclusive upper bound)
    reason: str  # end_of_life | known_vulnerable
    detail: str
    since: str | None = None  # ISO date the support ended, for the end of life of dated releases


@dataclass(frozen=True)
class Release:
    """One release line of a product with a dated end of support (PHP, IIS)."""

    prefix: tuple[int, ...]
    ends: str  # ISO date


# Dated support. The end dates are the vendors' published ones; distributions may keep patching an
# older version, which is why a finding on these says "upstream".
RELEASES: dict[str, tuple[Release, ...]] = {
    "php": (
        Release((5,), "2018-12-31"),
        Release((7, 0), "2018-12-03"),
        Release((7, 1), "2019-12-01"),
        Release((7, 2), "2020-11-30"),
        Release((7, 3), "2021-12-06"),
        Release((7, 4), "2022-11-28"),
        Release((8, 0), "2023-11-26"),
        Release((8, 1), "2025-12-31"),
        Release((8, 2), "2026-12-31"),
        Release((8, 3), "2027-12-31"),
        Release((8, 4), "2028-12-31"),
    ),
    "iis": (
        Release((5,), "2015-07-14"),
        Release((6,), "2015-07-14"),
        Release((7,), "2020-01-14"),
        Release((8,), "2023-10-10"),
    ),
    "drupal": (
        Release((7,), "2025-01-05"),
        Release((8,), "2021-11-02"),
        Release((9,), "2023-11-01"),
    ),
    "joomla": (
        Release((1,), "2012-01-01"),
        Release((2,), "2014-12-31"),
        Release((3,), "2023-08-17"),
    ),
}
# Whole lines that are no longer maintained, or versions with well-known vulnerabilities.
OLD: dict[str, tuple[Old, ...]] = {
    "apache": (
        Old((2, 4), "end_of_life", "Apache HTTP Server 2.2 and older ended in 2017", "2017-12-31"),
    ),
    "angularjs": (Old((2,), "end_of_life", "AngularJS 1.x ended in January 2022", "2022-01-01"),),
    "jquery": (
        Old(
            (3, 5),
            "known_vulnerable",
            "jQuery before 3.5.0 has cross-site scripting flaws in jQuery.htmlPrefilter "
            "(CVE-2020-11022, CVE-2020-11023)",
        ),
    ),
    "bootstrap": (
        Old(
            (5,),
            "end_of_life",
            "Bootstrap 4 and older ended in 2023 (version 3 in 2019)",
            "2023-01-01",
        ),
    ),
    "python": (Old((3,), "end_of_life", "Python 2 ended in January 2020", "2020-01-01"),),
}


def parse_version(text: str) -> tuple[int, ...] | None:
    """The numbers of a version such as ``8.1.2`` (at most four)."""
    found = re.match(r"\d+(?:\.\d+){0,3}", text.strip())
    return tuple(int(part) for part in found.group(0).split(".")) if found else None


def assess_version(key: str, version: str | None, today: datetime.date) -> dict[str, str] | None:
    """Is this version of a product old? ``{"reason", "detail", "since"}`` or ``None`` (not known
    to be, or not a product the ruleset has dates for: that is no statement that it is fine)."""
    parsed = parse_version(version) if version else None
    if parsed is None:
        return None
    for release in RELEASES.get(key, ()):
        if parsed[: len(release.prefix)] == release.prefix:
            ends = datetime.date.fromisoformat(release.ends)
            if ends < today:
                dotted = ".".join(str(part) for part in release.prefix)
                return {
                    "reason": "end_of_life",
                    "detail": f"{BY_KEY[key].name} {dotted} ended on {release.ends}",
                    "since": release.ends,
                }
            return None
    for old in OLD.get(key, ()):
        if parsed < old.below:
            return {"reason": old.reason, "detail": old.detail, "since": old.since or ""}
    return None


@dataclass
class Evidence:
    """One reason a technology was recognised (``kind`` is one of the evidence kinds above)."""

    kind: str
    detail: str


@dataclass
class Found:
    tech: Tech
    evidence: list[Evidence] = field(default_factory=list)
    version: str | None = None
    implied_by: str | None = None
