import voluptuous as vol
from homeassistant.config_entries import ConfigFlow

from .const import DOMAIN, CONF_API_BASE, CONF_PHONE, CONF_PHONE_IAC, CONF_PASSWORD, CONF_LANGUAGE, DEFAULT_API_BASE

ACCOUNT_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PHONE_IAC, default='86'): str,
        vol.Required(CONF_PHONE): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_API_BASE, default=DEFAULT_API_BASE): str,
        vol.Optional(CONF_LANGUAGE, default='zh_CN'): str,
    }
)


class CatlinkConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for the custom integration."""

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if user_input is not None:
            return self.async_create_entry(
                title="CatLink:" + user_input.get(CONF_PHONE_IAC) + user_input.get(CONF_PHONE),
                data=user_input,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=ACCOUNT_SCHEMA,
        )
