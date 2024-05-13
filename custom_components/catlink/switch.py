"""Support for switch."""
import asyncio
import logging

from homeassistant.components.switch import (
    SwitchEntity,
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


class CatlinkSwitchEntity(CatlinkBinaryEntity, SwitchEntity):

    async def async_turn_switch(self, on=True, **kwargs):
        """Turn the entity on/off."""
        ret = False
        fun = self._option.get('async_turn_on' if on else 'async_turn_off')
        if callable(fun):
            # kwargs['entity'] = self
            ret = await fun(**kwargs)
        if ret:
            self._attr_is_on = not not on
            self.async_write_ha_state()
            if dly := self._option.get('delay_update'):
                await asyncio.sleep(dly)
                self._handle_coordinator_update()
        return ret

    async def async_turn_on(self, **kwargs):
        """Turn the entity on."""
        return await self.async_turn_switch(True)

    async def async_turn_off(self, **kwargs):
        """Turn the entity off."""
        return await self.async_turn_switch(False)
