"""Support for binary_sensor."""
import logging

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    DOMAIN as ENTITY_DOMAIN,
)

from . import (
    DOMAIN,
    CatlinkBinaryEntity,
    async_setup_accounts,
)

_LOGGER = logging.getLogger(__name__)

DATA_KEY = f'{ENTITY_DOMAIN}.{DOMAIN}'


async def async_setup_entry(hass, config_entry, async_add_entities):
    hass.data[DOMAIN]['add_entities'][ENTITY_DOMAIN] = async_add_entities
    await async_setup_accounts(hass, ENTITY_DOMAIN)


class CatlinkBinarySensorEntity(CatlinkBinaryEntity, BinarySensorEntity):
    """ BinarySensorEntity """
