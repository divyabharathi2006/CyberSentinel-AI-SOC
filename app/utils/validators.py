from marshmallow import INCLUDE, Schema, ValidationError, fields, validate


class EventInputSchema(Schema):
    timestamp = fields.Raw(allow_none=True)
    source_ip = fields.String(allow_none=True, validate=validate.Length(max=45))
    destination_ip = fields.String(allow_none=True, validate=validate.Length(max=45))
    source_port = fields.Integer(allow_none=True, validate=validate.Range(min=1, max=65535))
    destination_port = fields.Integer(allow_none=True, validate=validate.Range(min=1, max=65535))
    protocol = fields.String(allow_none=True, validate=validate.Length(max=16))
    username = fields.String(allow_none=True, validate=validate.Length(max=128))
    hostname = fields.String(allow_none=True, validate=validate.Length(max=255))
    event_type = fields.String(required=True, validate=validate.Length(min=1, max=80))
    action = fields.String(allow_none=True, validate=validate.Length(max=80))
    status = fields.String(allow_none=True, validate=validate.Length(max=40))
    process = fields.String(allow_none=True, validate=validate.Length(max=255))
    message = fields.String(allow_none=True, validate=validate.Length(max=2000))
    severity = fields.String(allow_none=True, validate=validate.Length(max=20))
    source = fields.String(allow_none=True, validate=validate.Length(max=80))
    metadata = fields.Dict(allow_none=True)

    class Meta:
        unknown = INCLUDE


def validate_event_shape(payload: dict) -> dict:
    try:
        result = EventInputSchema().load(payload)
        known = set(EventInputSchema().fields)
        extra = {key: result.pop(key) for key in list(result) if key not in known}
        if extra:
            metadata = result.get("metadata") or {}
            result["metadata"] = {**metadata, **extra}
        return result
    except ValidationError as exc:
        message = "; ".join(f"{key}: {', '.join(messages)}" for key, messages in exc.messages.items())
        raise ValueError(message or "event payload is invalid") from exc
