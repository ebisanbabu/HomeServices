from typing import Dict


def apply_werkzeug_shim() -> bool:
    try:
        import werkzeug.urls as _wurls

        if not hasattr(_wurls, "url_decode"):
            from urllib.parse import parse_qsl

            def url_decode(qs, charset="utf-8", errors="replace", separator="&"):
                if qs is None:
                    return {}
                pairs = parse_qsl(qs, keep_blank_values=True, strict_parsing=False)
                result: Dict[str, list] = {}
                for k, v in pairs:
                    result.setdefault(k, []).append(v)
                return result

            _wurls.url_decode = url_decode

        if not hasattr(_wurls, "url_encode"):
            from urllib.parse import urlencode

            def url_encode(obj, charset="utf-8", errors="replace", safe=None, sort=False, doseq=True, **kwargs):
                if obj is None:
                    return ""
                try:
                    if isinstance(obj, dict):
                        items = list(obj.items())
                        if sort:
                            items = sorted(items)
                        return urlencode(items, doseq=doseq)
                    return urlencode(obj, doseq=doseq)
                except TypeError:
                    return str(obj)

            _wurls.url_encode = url_encode

        return True
    except Exception:
        return False


__all__ = ["apply_werkzeug_shim"]
