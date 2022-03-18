from collections.abc import Iterable

from django.utils.encoding import smart_str
from rest_framework.renderers import BaseRenderer


# Adapted from
# https://www.django-rest-framework.org/api-guide/renderers/#custom-renderers
class PlainTextRenderer(BaseRenderer):
    media_type = "text/plain"
    format = "text"

    def render(self, data, media_type=None, renderer_context=None):
        if isinstance(data, Iterable):
            return smart_str("\n".join(data), encoding=self.charset)
        return smart_str(data, encoding=self.charset)
