"""Advanced OpenAPI/Swagger spec parsing and targeting.

Extracts:
  - Security/auth schemes (Bearer, OAuth2, API-Key, etc.)
  - Parameter enums (test all enum values for business logic)
  - Request/response schemas (object fields for mass assignment)
  - Field constraints (min/max/pattern for boundary testing)
  - Request body schemas (POST/PUT payload structure)

This information informs attack design: mass assignment tests what fields
the spec says are writable, BOLA tests enum values from the spec, etc.
"""
import json


def extract_security_schemes(spec):
    """Extract auth schemes defined in the spec.

    Returns dict: {scheme_name: scheme_dict}
    Example: {"bearer": {"type": "apiKey", "in": "header"}, ...}
    """
    schemes = {}

    # Swagger 2.0
    if "securityDefinitions" in spec:
        schemes.update(spec["securityDefinitions"])

    # OpenAPI 3.0+
    if "components" in spec and "securitySchemes" in spec["components"]:
        schemes.update(spec["components"]["securitySchemes"])

    return schemes


def extract_parameter_enums(spec):
    """Extract all enum values for each parameter across all endpoints.

    Returns dict: {param_name: [enum_values]}
    Example: {"status": ["active", "inactive", "pending"], "role": ["admin", "user"]}
    """
    enums = {}

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, op in methods.items():
            if not isinstance(op, dict):
                continue

            # Parameters at path level
            for param in op.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                if not name:
                    continue

                # Swagger 2.0 style enum
                if "enum" in param:
                    enums.setdefault(name, []).extend(param["enum"])
                # OpenAPI 3.0 style (nested in schema)
                elif "schema" in param and isinstance(param["schema"], dict):
                    if "enum" in param["schema"]:
                        enums.setdefault(name, []).extend(param["schema"]["enum"])

            # Request body (OpenAPI 3.0)
            if "requestBody" in op and isinstance(op["requestBody"], dict):
                content = op["requestBody"].get("content", {})
                for ctype, cinfo in content.items():
                    schema = cinfo.get("schema", {})
                    if isinstance(schema, dict) and "properties" in schema:
                        for prop_name, prop_schema in schema["properties"].items():
                            if isinstance(prop_schema, dict) and "enum" in prop_schema:
                                enums.setdefault(prop_name, []).extend(prop_schema["enum"])

    # Deduplicate
    for key in enums:
        enums[key] = list(set(enums[key]))

    return enums


def extract_response_schemas(spec):
    """Extract response object schemas (fields) per endpoint.

    Returns dict: {path_method: {field_name: field_type}}
    Example: {"/users/{id}_GET": {"id": "integer", "name": "string", ...}}
    """
    schemas = {}

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, op in methods.items():
            if not isinstance(op, dict):
                continue

            # Look for 200 response with schema
            responses = op.get("responses", {})
            for status, resp_info in responses.items():
                if not status.startswith("2"):  # only 2xx
                    continue
                if not isinstance(resp_info, dict):
                    continue

                schema = None

                # Swagger 2.0
                if "schema" in resp_info:
                    schema = resp_info["schema"]

                # OpenAPI 3.0
                elif "content" in resp_info and isinstance(resp_info["content"], dict):
                    for ctype, cinfo in resp_info["content"].items():
                        if "schema" in cinfo:
                            schema = cinfo["schema"]
                            break

                if schema and isinstance(schema, dict):
                    if schema.get("type") == "object" and "properties" in schema:
                        key = f"{path}_{method.upper()}"
                        schemas[key] = {
                            name: prop.get("type", "string")
                            for name, prop in schema["properties"].items()
                            if isinstance(prop, dict)
                        }

    return schemas


def extract_field_constraints(spec):
    """Extract field constraints (min/max/pattern) for boundary testing.

    Returns dict: {field_name: {constraint_type: value}}
    Example: {"age": {"minimum": 0, "maximum": 150}, "email": {"pattern": "^[^@]+@[^@]+$"}}
    """
    constraints = {}

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, op in methods.items():
            if not isinstance(op, dict):
                continue

            # Parameters
            for param in op.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                schema = param.get("schema", param)  # Swagger 2.0 vs OpenAPI 3.0

                if isinstance(schema, dict):
                    cons = {}
                    for key in ["minimum", "maximum", "minLength", "maxLength", "pattern", "format"]:
                        if key in schema:
                            cons[key] = schema[key]
                    if cons and name:
                        constraints[name] = cons

            # Request body fields
            if "requestBody" in op and isinstance(op["requestBody"], dict):
                content = op["requestBody"].get("content", {})
                for ctype, cinfo in content.items():
                    schema = cinfo.get("schema", {})
                    if isinstance(schema, dict) and "properties" in schema:
                        for prop_name, prop_schema in schema["properties"].items():
                            if isinstance(prop_schema, dict):
                                cons = {}
                                for key in ["minimum", "maximum", "minLength", "maxLength", "pattern", "format"]:
                                    if key in prop_schema:
                                        cons[key] = prop_schema[key]
                                if cons:
                                    constraints[prop_name] = cons

    return constraints


def extract_request_body_schemas(spec):
    """Extract request body parameter names and types per endpoint.

    Useful for mass assignment testing: know what fields the spec says are writable.

    Returns dict: {path_method: {field_name: field_type}}
    """
    schemas = {}

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, op in methods.items():
            if not isinstance(op, dict):
                continue

            if method.upper() not in ["POST", "PUT", "PATCH"]:
                continue  # only request methods

            if "requestBody" not in op:
                continue

            req = op["requestBody"]
            if not isinstance(req, dict):
                continue

            content = req.get("content", {})
            for ctype, cinfo in content.items():
                if "schema" not in cinfo:
                    continue

                schema = cinfo["schema"]
                if isinstance(schema, dict) and schema.get("type") == "object":
                    key = f"{path}_{method.upper()}"
                    schemas[key] = {
                        name: prop.get("type", "string")
                        for name, prop in schema.get("properties", {}).items()
                        if isinstance(prop, dict)
                    }

    return schemas


def analyze_spec(spec_dict):
    """Run all extractors on a spec. Returns a comprehensive analysis dict."""
    return {
        "security_schemes": extract_security_schemes(spec_dict),
        "parameter_enums": extract_parameter_enums(spec_dict),
        "response_schemas": extract_response_schemas(spec_dict),
        "request_body_schemas": extract_request_body_schemas(spec_dict),
        "field_constraints": extract_field_constraints(spec_dict),
    }
