"""
PURL (Package URL) validation and normalization utilities.

Addresses SBOM issues from rpm-manifest-generator:
- 205,351 PURLs without versions
- 114,931 RPM PURLs missing distro namespace
- 203 malformed PURLs

This module ensures Aegis generates properly formatted PURLs that ACE/BOMQ can match reliably.
"""

import logging
from typing import Any

from packageurl import PackageURL

logger = logging.getLogger(__name__)


def validate_purl(purl_str: str | None, component_name: str, ecosystem: str) -> str | None:
    """
    Validate and normalize a PURL string.

    Args:
        purl_str: PURL string to validate
        component_name: Component name for error messages
        ecosystem: Expected ecosystem

    Returns:
        Normalized PURL string, or None if invalid
    """
    if not purl_str:
        return None

    try:
        purl = PackageURL.from_string(purl_str)

        # Validate ecosystem matches
        expected_type = _ecosystem_to_purl_type(ecosystem)
        if expected_type and purl.type != expected_type:
            logger.warning(
                f"PURL type mismatch for {component_name}: "
                f"got {purl.type}, expected {expected_type} for ecosystem {ecosystem}"
            )

        # Check for common issues
        if purl.type == "rpm" and not purl.namespace:
            logger.warning(
                f"RPM PURL missing namespace for {component_name}: {purl_str}. "
                f"Should be pkg:rpm/redhat/... or pkg:rpm/<distro>/..."
            )
            # Auto-fix: assume redhat namespace for RPMs
            purl = PackageURL(
                type="rpm",
                namespace="redhat",
                name=purl.name,
                version=purl.version,
                qualifiers=purl.qualifiers,
                subpath=purl.subpath,
            )
            logger.info(f"Auto-fixed RPM namespace: {purl}")

        if purl.type == "npm" and "/" in purl.name and not purl.name.startswith("%40"):
            logger.warning(
                f"npm PURL has unencoded scope separator for {component_name}: {purl_str}. "
                f"Scoped packages should use %40: pkg:npm/%40scope/package"
            )

        # Normalize to string
        return str(purl)

    except Exception as e:
        logger.warning(f"Invalid PURL for {component_name}: {purl_str}. Error: {e}")
        return None


def build_purl(
    ecosystem: str,
    name: str,
    namespace: str | None = None,
    version: str | None = None,
    qualifiers: dict[str, str] | None = None,
) -> str | None:
    """
    Build a properly formatted PURL from components.

    Args:
        ecosystem: Package ecosystem
        name: Package name
        namespace: Package namespace (required for some ecosystems)
        version: Package version
        qualifiers: Additional qualifiers (e.g., epoch for RPMs)

    Returns:
        Formatted PURL string, or None if cannot construct

    Examples:
        >>> build_purl("golang", "rclone", "github.com/rclone", "1.75.0")
        'pkg:golang/github.com/rclone/rclone@1.75.0'

        >>> build_purl("rpm", "python-cffi", "redhat", "2.0.0-2.el10ap")
        'pkg:rpm/redhat/python-cffi@2.0.0-2.el10ap'

        >>> build_purl("maven", "spring-webmvc", "org.springframework", "5.3.21")
        'pkg:maven/org.springframework/spring-webmvc@5.3.21'
    """
    try:
        purl_type = _ecosystem_to_purl_type(ecosystem)
        if not purl_type:
            logger.warning(f"Cannot map ecosystem '{ecosystem}' to PURL type")
            return None

        # Special handling for Go modules: full path in name
        if purl_type == "golang" and namespace:
            name = f"{namespace}/{name}"
            namespace = None  # Go PURLs don't use namespace field

        purl = PackageURL(
            type=purl_type,
            namespace=namespace,
            name=name,
            version=version,
            qualifiers=qualifiers,
        )

        return str(purl)

    except Exception as e:
        logger.warning(
            f"Failed to build PURL for {ecosystem}/{namespace}/{name}: {e}"
        )
        return None


def extract_namespace_from_name(name: str, ecosystem: str) -> tuple[str, str | None]:
    """
    Extract namespace from component name if embedded.

    Args:
        name: Component name (may include namespace)
        ecosystem: Package ecosystem

    Returns:
        Tuple of (pure_name, namespace)

    Examples:
        >>> extract_namespace_from_name("org.springframework/spring-webmvc", "maven")
        ('spring-webmvc', 'org.springframework')

        >>> extract_namespace_from_name("github.com/rclone/rclone", "golang")
        ('rclone', 'github.com/rclone')

        >>> extract_namespace_from_name("@patternfly/react-core", "npm")
        ('react-core', '@patternfly')

        >>> extract_namespace_from_name("cryptography", "pypi")
        ('cryptography', None)
    """
    # Maven: groupId/artifactId
    if ecosystem == "maven" and "/" in name:
        parts = name.rsplit("/", 1)
        return (parts[1], parts[0])

    # Go: full module path
    if ecosystem == "golang" and "/" in name:
        parts = name.rsplit("/", 1)
        return (parts[1], parts[0])

    # npm: @scope/package
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        parts = name.split("/", 1)
        return (parts[1], parts[0])

    # PHP Composer: vendor/package
    if ecosystem == "composer" and "/" in name:
        parts = name.rsplit("/", 1)
        return (parts[1], parts[0])

    # No namespace
    return (name, None)


def _ecosystem_to_purl_type(ecosystem: str) -> str | None:
    """Map Aegis ecosystem names to PURL type identifiers."""
    mapping = {
        "cargo": "cargo",
        "golang": "golang",
        "npm": "npm",
        "pypi": "pypi",
        "maven": "maven",
        "gem": "gem",
        "generic": "generic",
        "composer": "composer",
        "rpm": "rpm",
        "deb": "deb",
    }
    return mapping.get(ecosystem.lower())


def validate_component_match(component: Any) -> dict[str, Any]:
    """
    Validate and normalize a ComponentMatch object.

    Args:
        component: ComponentMatch instance or dict

    Returns:
        Dict with validation warnings and normalized values
    """
    warnings = []

    # Extract fields
    if hasattr(component, "model_dump"):
        data = component.model_dump()
    else:
        data = dict(component)

    name = data.get("name")
    namespace = data.get("namespace")
    ecosystem = data.get("ecosystem")
    purl = data.get("purl")

    # Validate PURL if present
    if purl:
        normalized_purl = validate_purl(purl, name, ecosystem)
        if normalized_purl != purl:
            warnings.append(f"PURL normalized: {purl} → {normalized_purl}")
            data["purl"] = normalized_purl

    # Check for required namespace by ecosystem
    if ecosystem == "rpm" and not namespace:
        warnings.append(
            f"RPM component '{name}' missing namespace (should be 'redhat' or distro name)"
        )

    if ecosystem == "maven" and "/" not in name and not namespace:
        warnings.append(
            f"Maven component '{name}' missing groupId (namespace or in name as groupId/artifactId)"
        )

    # Check for version in PURL
    if purl and "@" not in purl and ecosystem not in ("generic", "unknown"):
        warnings.append(
            f"PURL for '{name}' missing version. This creates versionless PURLs that cannot be matched."
        )

    return {"warnings": warnings, "normalized": data}
