from django.utils.encoding import smart_text
from rest_framework.renderers import BaseRenderer


# Adapted from
# https://www.django-rest-framework.org/api-guide/renderers/#custom-renderers
class PlainTextRenderer(BaseRenderer):
    media_type = "text/plain"
    format = "text"

    def render(self, data, media_type=None, renderer_context=None):
        if isinstance(data, list):
            return smart_text("\n".join(data), encoding=self.charset)
        return smart_text(data, encoding=self.charset)
