from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlow, ConfigEntry
from homeassistant.core import callback

from .const import DOMAIN, CONF_API_BASE, CONF_PHONE, CONF_PHONE_IAC, CONF_PASSWORD, CONF_LANGUAGE, DEFAULT_API_BASE

ACCOUNT_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PHONE_IAC, default='86'): str,
        vol.Required(CONF_PHONE): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_API_BASE, default=DEFAULT_API_BASE): str,
        vol.Optional(CONF_LANGUAGE, default='zh_CN'): str,
        # vol.Optional(CONF_SCAN_INTERVAL, default='00:01:00'): vol.All(cv.time_period_str),
    }
)


class CatlinkConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for the custom integration."""

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if user_input is not None:
            return self.async_create_entry(
                title="CatLink",
                data=user_input,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=ACCOUNT_SCHEMA,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow handler for the config entry."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(OptionsFlow):
    """Handle options flow for the custom integration."""

    def __init__(self, config_entry: ConfigEntry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
            self, user_input: dict[str, Any] | None = None):
        """Manage the options."""
        if user_input is not None:
            opt = {}
            for k, v in user_input.items():
                if k not in [CONF_PHONE, CONF_PHONE_IAC, CONF_PASSWORD]:
                    opt[k] = v
            self.hass.config_entries.async_update_entry(
                self.config_entry, options=opt
            )
            return self.async_create_entry(title="", data={})

        user_input = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PHONE_IAC, default=user_input.get(CONF_PHONE_IAC, '86')): str,
                    vol.Required(CONF_PHONE, default=user_input.get(CONF_PHONE, "")): str,
                    vol.Required(CONF_PASSWORD, default=user_input.get(CONF_PASSWORD, "")): str,
                    vol.Optional(CONF_API_BASE, default=user_input.get(CONF_API_BASE, DEFAULT_API_BASE)): str,
                    vol.Optional(CONF_LANGUAGE, default=user_input.get(CONF_LANGUAGE, 'zh_CN')): str,
                    # vol.Optional(CONF_SCAN_INTERVAL, default=options.get(CONF_SCAN_INTERVAL, '00:01:00')): vol.All(
                    #     cv.time_period_str),
                }
            ),
            description_placeholders={
                CONF_PHONE_IAC: "Phone IAC (read-only)",
                CONF_PHONE: "Phone number (read-only)",
                CONF_PASSWORD: "Password (read-only)"
            }
        )
