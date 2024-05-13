"""Support for sensor."""
import logging

import voluptuous as vol
from homeassistant.components.sensor import (
    SensorEntity,
    DOMAIN as ENTITY_DOMAIN,
)
from homeassistant.helpers import config_validation as cv, entity_platform

from . import (
    CatlinkEntity,
    async_setup_accounts, DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

DATA_KEY = f'{ENTITY_DOMAIN}.{DOMAIN}'


async def async_setup_entry(hass, config_entry, async_add_entities):
    hass.data[DOMAIN]['add_entities'][ENTITY_DOMAIN] = async_add_entities
    await async_setup_accounts(hass, ENTITY_DOMAIN)

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        'request_api',
        {
            vol.Required('api'): cv.string,
            vol.Optional('params', default={}): vol.Any(dict, None),
            vol.Optional('method', default='GET'): cv.string,
            vol.Optional('throw', default=True): cv.boolean,
        },
        'async_request_api',
    )


class CatlinkSensorEntity(CatlinkEntity, SensorEntity):
    """ SensorEntity """
