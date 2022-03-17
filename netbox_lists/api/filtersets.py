import django_filters
from django.db.models import Q
from ipam.filtersets import PrefixFilterSet


class CustomPrefixFilterSet(PrefixFilterSet):
    mask_length4 = django_filters.NumberFilter(
        field_name="prefix", method="filter_mask_length4"
    )
    mask_length4__lte = django_filters.NumberFilter(
        field_name="prefix", method="filter_mask_length4__lte"
    )
    mask_length4__gte = django_filters.NumberFilter(
        field_name="prefix", method="filter_mask_length4__gte"
    )

    mask_length6 = django_filters.NumberFilter(
        field_name="prefix", method="filter_mask_length6"
    )
    mask_length6__lte = django_filters.NumberFilter(
        field_name="prefix", method="filter_mask_length6__lte"
    )
    mask_length6__gte = django_filters.NumberFilter(
        field_name="prefix", method="filter_mask_length6__gte"
    )

    def _generic_mask_filter(self, queryset, op, family, val):
        assert op in ["gte", "lte", "exact"]
        assert family in [4, 6]

        opposite_family = 4 if family == 6 else 6

        return queryset.filter(
            Q(Q(prefix__family=family) & Q(**{f"prefix__net_mask_length__{op}": val}))
            | Q(prefix__family=opposite_family)
        )

    def filter_mask_length4(self, qs, name, value):
        return self._generic_mask_filter(qs, "exact", 4, value)

    def filter_mask_length4__lte(self, qs, name, value):
        return self._generic_mask_filter(qs, "lte", 4, value)

    def filter_mask_length4__gte(self, qs, name, value):
        return self._generic_mask_filter(qs, "gte", 4, value)

    def filter_mask_length6(self, qs, name, value):
        return self._generic_mask_filter(qs, "exact", 6, value)

    def filter_mask_length6__lte(self, qs, name, value):
        return self._generic_mask_filter(qs, "lte", 6, value)

    def filter_mask_length6__gte(self, qs, name, value):
        return self._generic_mask_filter(qs, "gte", 6, value)
