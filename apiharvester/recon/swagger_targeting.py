"""Helper functions for attacks to use swagger analysis data.

Example usage in an attack module:

    from .swagger_targeting import get_enum_values, get_writable_fields

    # Test all enum values for a parameter
    for ep in ctx.endpoints:
        if "status" in ctx.swagger_analysis:
            status_values = get_enum_values(ctx, "status", ep.host)
            for val in status_values:
                # Test with this value

    # Get fields that specs says are writable (POST/PUT/PATCH bodies)
    for ep in ctx.endpoints:
        if ep.methods and "PUT" in ep.methods:
            writable = get_writable_fields(ctx, ep)
            # Try injecting into these fields for mass assignment
"""


def get_enum_values(ctx, param_name, domain):
    """Get all enum values for a parameter from the spec.

    Returns list of enum values, or empty list if not found.
    """
    if domain not in ctx.swagger_analysis:
        return []
    analysis = ctx.swagger_analysis[domain]
    enums = analysis.get("parameter_enums", {})
    return enums.get(param_name, [])


def get_writable_fields(ctx, endpoint):
    """Get fields that the spec says are writable in the request body.

    Returns dict: {field_name: field_type}, or empty dict if not found.
    """
    if not endpoint.host or endpoint.host not in ctx.swagger_analysis:
        return {}

    analysis = ctx.swagger_analysis[endpoint.host]
    request_schemas = analysis.get("request_body_schemas", {})

    # Find the matching endpoint in request schemas
    # Keys are formatted as "{path}_{METHOD}"
    path_method_variants = [
        f"{endpoint.path}_POST",
        f"{endpoint.path}_PUT",
        f"{endpoint.path}_PATCH",
        # Try without trailing slash too
        f"{endpoint.path.rstrip('/')}_POST",
        f"{endpoint.path.rstrip('/')}_PUT",
        f"{endpoint.path.rstrip('/')}_PATCH",
    ]

    for variant in path_method_variants:
        if variant in request_schemas:
            return request_schemas[variant]

    return {}


def get_response_fields(ctx, endpoint):
    """Get object fields that the spec says are in the response.

    Returns dict: {field_name: field_type}, or empty dict if not found.
    """
    if not endpoint.host or endpoint.host not in ctx.swagger_analysis:
        return {}

    analysis = ctx.swagger_analysis[endpoint.host]
    response_schemas = analysis.get("response_schemas", {})

    # Keys are formatted as "{path}_{METHOD}"
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        key = f"{endpoint.path}_{method}"
        if key in response_schemas:
            return response_schemas[key]

    return {}


def get_field_constraints(ctx, field_name):
    """Get validation constraints (min/max/pattern) for a field.

    Returns dict: {"minimum": X, "maximum": Y, "pattern": "...", ...}
    """
    if not ctx.swagger_analysis:
        return {}

    for analysis in ctx.swagger_analysis.values():
        constraints = analysis.get("field_constraints", {})
        if field_name in constraints:
            return constraints[field_name]

    return {}


def get_auth_schemes(ctx, domain):
    """Get auth schemes the spec says are required.

    Returns dict of scheme definitions.
    """
    if domain not in ctx.swagger_analysis:
        return {}
    analysis = ctx.swagger_analysis[domain]
    return analysis.get("security_schemes", {})
