import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import callback

from .const import DOMAIN, CONF_API_BASE, CONF_PHONE, CONF_PHONE_IAC, CONF_PASSWORD, CONF_LANGUAGE, DEFAULT_API_BASE

ACCOUNT_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_API_BASE, default=DEFAULT_API_BASE): str,
        vol.Required(CONF_PHONE): str,
        vol.Required(CONF_PHONE_IAC, default='86'): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_LANGUAGE, default='zh_CN'): str,
        vol.Optional(CONF_SCAN_INTERVAL, default='00:01:00'): vol.All(cv.time_period_str),
    }
)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
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
    def async_get_options_flow(config_entry):
        """Return the options flow handler for the config entry."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for the custom integration."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            self.hass.config_entries.async_update_entry(
                self.config_entry, options=user_input
            )
            return self.async_create_entry(title="", data={})

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_API_BASE, default=options.get(CONF_API_BASE, DEFAULT_API_BASE)): str,
                    vol.Required(CONF_PHONE, default=options.get(CONF_PHONE, "")): str,
                    vol.Required(CONF_PHONE_IAC, default=options.get(CONF_PHONE_IAC, '86')): str,
                    vol.Required(CONF_PASSWORD, default=options.get(CONF_PASSWORD, "")): str,
                    vol.Optional(CONF_LANGUAGE, default=options.get(CONF_LANGUAGE, 'zh_CN')): str,
                    vol.Optional(CONF_SCAN_INTERVAL, default=options.get(CONF_SCAN_INTERVAL, '00:01:00')): vol.All(
                        cv.time_period_str),
                }
            ),
        )
