"""The component."""
import asyncio
import base64
import datetime
import hashlib
import logging
import time
from asyncio import TimeoutError

from aiohttp import ClientConnectorError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from homeassistant.components import persistent_notification
from homeassistant.components.binary_sensor import (
    DOMAIN as BINARY_SENSOR_DOMAIN,
)
from homeassistant.components.button import (
    DOMAIN as BUTTON_DOMAIN,
)
from homeassistant.components.select import (
    DOMAIN as SELECT_DOMAIN,
)
from homeassistant.components.sensor import (
    DOMAIN as SENSOR_DOMAIN,
)
from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.components.switch import (
    DOMAIN as SWITCH_DOMAIN,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_TOKEN, CONF_DEVICES, CONF_PASSWORD, CONF_SCAN_INTERVAL, \
    CONF_LANGUAGE, UnitOfTemperature, UnitOfMass, PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

_LOGGER = logging.getLogger(__name__)

from .const import DOMAIN, CONF_API_BASE, CONF_PHONE, CONF_PHONE_IAC, CONF_PASSWORD, CONF_LANGUAGE, CONF_SCAN_INTERVAL, \
    DEFAULT_API_BASE, SCAN_INTERVAL, CONF_ACCOUNTS, SIGN_KEY, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY

SUPPORTED_DOMAINS = [
    SENSOR_DOMAIN,
    BINARY_SENSOR_DOMAIN,
    SWITCH_DOMAIN,
    SELECT_DOMAIN,
    BUTTON_DOMAIN,
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Catlink from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    # Get the session and create your API client here
    acc = Account(hass, dict(entry.data))
    coordinator = DevicesCoordinator(acc)

    # Fetch initial data
    await acc.async_check_auth()
    await coordinator.async_config_entry_first_refresh()

    # Store the coordinator
    hass.data[DOMAIN][CONF_ACCOUNTS][acc.uid] = acc
    hass.data[DOMAIN]['coordinators'][entry.entry_id] = coordinator

    # Register the device in the device registry
    for dvc in coordinator.device_list:
        device_registry = dr.async_get(hass)
        device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, dvc.id)},
            name=dvc.name,
            manufacturer="CatLink",
            model=dvc.model,
            sw_version=dvc.firmwareVersion,
        )
        _LOGGER.debug(f"Registering device: {dvc.id}, {dvc.name}")

    for platform in SUPPORTED_DOMAINS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setups(entry, [platform])
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(entry, sd)
                for sd in SUPPORTED_DOMAINS
            ]
        )
    )
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


async def async_setup(hass: HomeAssistant, hass_config: dict):
    hass.data.setdefault(DOMAIN, {
        CONF_ACCOUNTS: {},
        CONF_DEVICES: {},
        'coordinators': {},
        'add_entities': {},
    })
    return True


async def async_setup_accounts(hass: HomeAssistant, domain):
    for coordinator in hass.data[DOMAIN]['coordinators'].values():
        for k, sta in coordinator.data.items():
            await coordinator.update_hass_entities(domain, sta)


class Account:
    def __init__(self, hass: HomeAssistant, config: dict):
        self._config = config
        self.hass = hass
        self.http = aiohttp_client.async_create_clientsession(hass, auto_cleanup=False)

    def get_config(self, key, default=None):
        return self._config.get(key, default)

    @property
    def phone(self):
        return self._config.get(CONF_PHONE)

    @property
    def password(self):
        pwd = self._config.get(CONF_PASSWORD)
        if len(pwd) <= 16:
            pwd = self.encrypt_password(pwd)
        return pwd

    @property
    def uid(self):
        return f'{self._config.get(CONF_PHONE_IAC)}-{self.phone}'

    @property
    def token(self):
        return self._config.get(CONF_TOKEN) or ''

    @property
    def update_interval(self):
        return self.get_config(CONF_SCAN_INTERVAL) or SCAN_INTERVAL

    def api_url(self, api=''):
        if api[:6] == 'https:' or api[:5] == 'http:':
            return api
        bas = self.get_config(CONF_API_BASE) or DEFAULT_API_BASE
        return f"{bas.rstrip('/')}/{api.lstrip('/')}"

    async def request(self, api, pms=None, method='GET', **kwargs):
        method = method.upper()
        url = self.api_url(api)
        kws = {
            'timeout': 60,
            'headers': {
                'language': self.get_config(CONF_LANGUAGE),
                'User-Agent': 'okhttp/3.10.0',
            },
        }
        kws.update(kwargs)
        if pms is None:
            pms = {}
        pms['noncestr'] = int(time.time() * 1000)
        if self.token:
            pms[CONF_TOKEN] = self.token
        pms['sign'] = self.params_sign(pms)
        if method in ['GET']:
            kws['params'] = pms
        elif method in ['POST_GET']:
            method = 'POST'
            kws['params'] = pms
        else:
            kws['data'] = pms
        try:
            _LOGGER.debug("Send request %s %s, Params:%s", method, url, pms)
            req = await self.http.request(method, url, **kws)
            resp = await req.json() or {}
            _LOGGER.debug("Send request %s %s, Response:%s", method, url, resp)
            return resp
        except (ClientConnectorError, TimeoutError) as exc:
            _LOGGER.error('Request api failed: %s', [method, url, pms, exc])
        return {}

    async def async_login(self):
        pms = {
            'platform': 'ANDROID',
            'internationalCode': self._config.get(CONF_PHONE_IAC),
            'mobile': self.phone,
            'password': self.password,
        }
        self._config.update({
            CONF_TOKEN: None,
        })
        rsp = await self.request('login/password', pms, 'POST')
        tok = rsp.get('data', {}).get('token')
        if not tok:
            _LOGGER.error('Login %s failed: %s', self.phone, [rsp, pms])
            return False
        self._config.update({
            CONF_TOKEN: tok,
        })
        await self.async_check_auth(True)
        return True

    async def async_check_auth(self, save=False):
        fnm = f'{DOMAIN}/auth-{self.uid}.json'
        sto = Store(self.hass, 1, fnm)
        old = await sto.async_load() or {}
        if save:
            cfg = {
                CONF_PHONE: self.phone,
                CONF_TOKEN: self.token,
            }
            if cfg.get(CONF_TOKEN) == old.get(CONF_TOKEN):
                cfg['update_at'] = old.get('update_at')
            else:
                cfg['update_at'] = f'{datetime.datetime.today()}'
            await sto.async_save(cfg)
            return cfg
        if old.get(CONF_TOKEN):
            self._config.update({
                CONF_TOKEN: old.get(CONF_TOKEN),
            })
        else:
            await self.async_login()
        return old

    async def get_devices(self):
        if not self.token:
            if not await self.async_login():
                return []
        api = 'token/device/union/list/sorted'
        rsp = await self.request(api, {'type': 'NONE'})
        eno = rsp.get('returnCode', 0)
        if eno == 1002:  # Illegal token
            if await self.async_login():
                rsp = await self.request(api, {'type': 'NONE'})
        dls = rsp.get('data', {}).get(CONF_DEVICES) or []
        if not dls:
            _LOGGER.warning('Got devices for %s failed: %s', self.phone, rsp)
        return dls

    @staticmethod
    def params_sign(pms: dict):
        lst = list(pms.items())
        lst.sort()
        pms = [
            f'{k}={v}'
            for k, v in lst
        ]
        pms.append(f'key={SIGN_KEY}')
        pms = '&'.join(pms)
        return hashlib.md5(pms.encode()).hexdigest().upper()

    @staticmethod
    def encrypt_password(pwd):
        pwd = f'{pwd}'
        md5 = hashlib.md5(pwd.encode()).hexdigest().lower()
        sha = hashlib.sha1(md5.encode()).hexdigest().upper()
        pub = serialization.load_der_public_key(base64.b64decode(RSA_PUBLIC_KEY), default_backend())
        pad = padding.PKCS1v15()
        return base64.b64encode(pub.encrypt(sha.encode(), pad)).decode()


class DevicesCoordinator(DataUpdateCoordinator):
    def __init__(self, account: Account):
        super().__init__(
            account.hass,
            _LOGGER,
            name=f'{DOMAIN}-{account.uid}-{CONF_DEVICES}',
            update_interval=account.update_interval,
        )
        self.account = account
        self._subs = {}

    async def _async_update_data(self):
        dls = await self.account.get_devices()
        self.device_list = []
        for dat in dls:
            did = dat.get('id')
            if not did:
                continue
            old = self.hass.data[DOMAIN][CONF_DEVICES].get(did)
            if old:
                dvc = old
                dvc.update_data(dat)
            else:
                typ = dat.get('deviceType')
                if typ in ['SCOOPER']:
                    dvc = ScooperDevice(dat, self)
                elif typ in ['FEEDER']:
                    dvc = FeederDevice(dat, self)
                else:
                    dvc = Device(dat, self)
                self.hass.data[DOMAIN][CONF_DEVICES][did] = dvc
            await dvc.async_init()
            for d in SUPPORTED_DOMAINS:
                await self.update_hass_entities(d, dvc)
            self.device_list.append(dvc)
        return self.hass.data[DOMAIN][CONF_DEVICES]

    async def update_hass_entities(self, domain, dvc):
        from .sensor import CatlinkSensorEntity
        from .binary_sensor import CatlinkBinarySensorEntity
        from .switch import CatlinkSwitchEntity
        from .select import CatlinkSelectEntity
        from .button import CatlinkButtonEntity
        hdk = f'hass_{domain}'
        add = self.hass.data[DOMAIN]['add_entities'].get(domain)
        if not add or not hasattr(dvc, hdk):
            return
        for k, cfg in getattr(dvc, hdk).items():
            key = f'{domain}.{k}.{dvc.id}'
            new = None
            if key in self._subs:
                pass
            elif domain == 'sensor':
                new = CatlinkSensorEntity(k, dvc, cfg)
            elif domain == 'binary_sensor':
                new = CatlinkBinarySensorEntity(k, dvc, cfg)
            elif domain == 'switch':
                new = CatlinkSwitchEntity(k, dvc, cfg)
            elif domain == 'select':
                new = CatlinkSelectEntity(k, dvc, cfg)
            elif domain == 'button':
                new = CatlinkButtonEntity(k, dvc, cfg)
            if new:
                self._subs[key] = new
                add([new])


class Device:
    data: dict

    def __init__(self, dat: dict, coordinator: DevicesCoordinator):
        self.coordinator = coordinator
        self.account = coordinator.account
        self.listeners = {}
        self.update_data(dat)
        self.detail = {}

    async def async_init(self):
        await self.update_device_detail()
        self.logs = []
        self.coordinator_logs = DataUpdateCoordinator(
            self.account.hass,
            _LOGGER,
            name=f'{DOMAIN}-{self.id}-logs',
            update_method=self.update_logs,
            update_interval=datetime.timedelta(minutes=1),
        )
        await self.coordinator_logs.async_config_entry_first_refresh()

    async def update_device_detail(self):
        pass

    async def update_logs(self):
        pass

    def update_data(self, dat: dict):
        self.data = dat
        self._handle_listeners()
        _LOGGER.debug('Update device data: %s', dat)

    def _handle_listeners(self):
        for fun in self.listeners.values():
            fun()

    @property
    def id(self):
        return self.data.get('id')

    @property
    def mac(self):
        return self.data.get('mac', '')

    @property
    def model(self):
        return self.data.get('model', '')

    @property
    def type(self):
        return self.data.get('deviceType', '')

    @property
    def name(self):
        return self.data.get('deviceName', '')

    @property
    def firmwareVersion(self):
        return self.detail.get('firmwareVersion', '')


class FeederDevice(Device):
    logs: list
    coordinator_logs = None

    @property
    def weight(self):
        return self.detail.get('weight')

    @property
    def error(self):
        return self.detail.get('error')

    def error_attrs(self):
        return {
            'currentErrorMessage': self.detail.get('currentErrorMessage'),
            'currentErrorType': self.detail.get('currentErrorType'),
        }

    async def update_device_detail(self):
        api = 'token/device/feeder/detail'
        pms = {
            'deviceId': self.id,
        }
        rsp = None
        try:
            rsp = await self.account.request(api, pms)
            rdt = rsp.get('data', {}).get('deviceInfo') or {}
        except (TypeError, ValueError) as exc:
            rdt = {}
            _LOGGER.error('Got device detail for %s failed: %s', self.name, exc)
        if not rdt:
            _LOGGER.warning('Got device detail for %s failed: %s', self.name, rsp)
        _LOGGER.debug('Update device detail: %s', rsp)
        self.detail = rdt
        self._handle_listeners()
        return rdt

    @property
    def state(self):
        return self.detail.get('foodOutStatus')

    def state_attrs(self):
        return {
            'work_status': self.detail.get('foodOutStatus'),
            'auto_fill_status': self.detail.get('autoFillStatus'),
            'indicator_light_status': self.detail.get('indicatorLightStatus'),
            'breath_light_status': self.detail.get('breathLightStatus'),
            'power_supply_status': self.detail.get('powerSupplyStatus'),
            'key_lock_status': self.detail.get('keyLockStatus'),
        }

    @property
    def _last_log(self):
        log = {}
        if self.logs:
            log = self.logs[0] or {}
        return log

    @property
    def last_log(self):
        log = self._last_log
        if not log:
            return None
        return f"{log.get('time')} {log.get('event')} {log.get('firstSection')} {log.get('secondSection')}".strip()

    def last_log_attrs(self):
        log = self._last_log
        return {
            **log,
            'logs': self.logs,
        }

    async def update_logs(self):
        api = 'token/device/feeder/stats/log/top5'
        pms = {
            'deviceId': self.id,
        }
        rsp = None
        try:
            rsp = await self.account.request(api, pms)
            rdt = rsp.get('data', {}).get('feederLogTop5') or []
        except (TypeError, ValueError) as exc:
            rdt = {}
            _LOGGER.warning('Got device logs for %s failed: %s', self.name, exc)
        if not rdt:
            _LOGGER.debug('Got device logs for %s failed: %s', self.name, rsp)
        _LOGGER.debug('Update device logs: %s', rsp)
        self.logs = rdt
        self._handle_listeners()
        return rdt

    async def food_out(self):
        api = 'token/device/feeder/foodOut'
        pms = {
            'footOutNum': 5,
            'deviceId': self.id,
        }
        rdt = await self.account.request(api, pms, 'POST')
        eno = rdt.get('returnCode', 0)
        if eno:
            _LOGGER.error('Food out failed: %s', [rdt, pms])
            return False
        await self.update_device_detail()
        _LOGGER.info('Food out: %s', [rdt, pms])
        return rdt

    @property
    def hass_sensor(self):
        return {
            'state': {
                'icon': 'mdi:information',
                'state_attrs': self.state_attrs,
            },
            'weight': {
                'icon': 'mdi:weight-gram',
                'state': self.weight,
                'device_class': SensorDeviceClass.WEIGHT,
                'unit': UnitOfMass.GRAMS,
                "state_class": SensorStateClass.MEASUREMENT
            },
            'error': {
                'icon': 'mdi:alert-circle',
                'state': self.error,
                'state_attrs': self.error_attrs,
            },
            'last_log': {
                'icon': 'mdi:message',
                'state': self.last_log,
                'state_attrs': self.last_log_attrs,
            },
        }

    @property
    def hass_button(self):
        return {
            'feed': {
                'icon': 'mdi:food',
                'async_press': self.food_out,
            }
        }


class ScooperDevice(Device):
    logs: list
    coordinator_logs = None

    async def update_device_detail(self):
        api = 'token/device/info'
        pms = {
            'deviceId': self.id,
        }
        rsp = None
        try:
            rsp = await self.account.request(api, pms)
            rdt = rsp.get('data', {}).get('deviceInfo') or {}
        except (TypeError, ValueError) as exc:
            rdt = {}
            _LOGGER.error('Got device detail for %s failed: %s', self.name, exc)
        if not rdt:
            _LOGGER.warning('Got device detail for %s failed: %s', self.name, rsp)
        _LOGGER.debug('Update device detail: %s', rsp)
        self.detail = rdt
        self._handle_listeners()
        return rdt

    @property
    def state(self):
        sta = self.detail.get('workStatus', '')
        dic = {
            '00': 'idle',
            '01': 'running',
            '02': 'need_reset',
        }
        return dic.get(f'{sta}'.strip(), sta)

    def state_attrs(self):
        return {
            'work_status': self.detail.get('workStatus'),
            'alarm_status': self.detail.get('alarmStatus'),
            'atmosphere_status': self.detail.get('atmosphereStatus'),
            'weight': self.detail.get('weight'),
            'key_lock': self.detail.get('keyLock'),
            'safe_time': self.detail.get('safeTime'),
            'pave_second': self.detail.get('catLitterPaveSecond'),
        }

    @property
    def temperature(self):
        return self.detail.get('temperature')

    @property
    def humidity(self):
        return self.detail.get('humidity')

    @property
    def catLitterWeight(self):
        return self.detail.get('catLitterWeight')

    @property
    def mode(self):
        return self.modes.get(self.detail.get('workModel', ''))

    def mode_attrs(self):
        return {
            'work_mode': self.detail.get('workModel'),
        }

    @property
    def modes(self):
        return {
            '00': 'auto',
            '01': 'manual',
            '02': 'time',
            '03': 'empty',
        }

    @property
    def action(self):
        return None

    @property
    def actions(self):
        return {
            '00': 'pause',
            '01': 'start',
        }

    @property
    def _last_log(self):
        log = {}
        if self.logs:
            log = self.logs[0] or {}
        return log

    @property
    def last_log(self):
        log = self._last_log
        if not log:
            return None
        return f"{log.get('time')} {log.get('event')} {log.get('firstSection')} {log.get('secondSection')}".strip()

    def last_log_attrs(self):
        log = self._last_log
        return {
            **log,
            'logs': self.logs,
        }

    @property
    def error(self):
        current_message = self.detail.get('currentMessage')
        if '' == current_message:
            current_message = 'NORMAL'
        return current_message

    def error_attrs(self):
        return {

        }

    async def update_logs(self):
        api = 'token/device/scooper/stats/log/top5'
        pms = {
            'deviceId': self.id,
        }
        rsp = None
        try:
            rsp = await self.account.request(api, pms)
            rdt = rsp.get('data', {}).get('scooperLogTop5') or []
        except (TypeError, ValueError) as exc:
            rdt = {}
            _LOGGER.warning('Got device logs for %s failed: %s', self.name, exc)
        if not rdt:
            _LOGGER.debug('Got device logs for %s failed: %s', self.name, rsp)
        _LOGGER.debug('Update device logs: %s', rsp)
        self.logs = rdt
        self._handle_listeners()
        return rdt

    async def select_mode(self, mode, **kwargs):
        api = 'token/device/changeMode'
        mod = None
        for k, v in self.modes.items():
            if v == mode:
                mod = k
                break
        if mod is None:
            _LOGGER.warning('Select mode failed for %s in %s', mode, self.modes)
            return False
        pms = {
            'workModel': mod,
            'deviceId': self.id,
        }
        rdt = await self.account.request(api, pms, 'POST')
        eno = rdt.get('returnCode', 0)
        if eno:
            _LOGGER.error('Select mode failed: %s', [rdt, pms])
            return False
        await self.update_device_detail()
        _LOGGER.info('Select mode: %s', [rdt, pms])
        return rdt

    async def select_action(self, action, **kwargs):
        api = 'token/device/actionCmd'
        val = None
        for k, v in self.actions.items():
            if v == action:
                val = k
                break
        if val is None:
            _LOGGER.warning('Select action failed for %s in %s', action, self.actions)
            return False
        pms = {
            'cmd': val,
            'deviceId': self.id,
        }
        rdt = await self.account.request(api, pms, 'POST')
        eno = rdt.get('returnCode', 0)
        if eno:
            _LOGGER.error('Select action failed: %s', [rdt, pms])
            return False
        await self.update_device_detail()
        _LOGGER.info('Select action: %s', [rdt, pms])
        return rdt

    @property
    def hass_sensor(self):
        return {
            'state': {
                'icon': 'mdi:information',
                'state_attrs': self.state_attrs,
            },
            'temperature': {
                'icon': 'mdi:temperature-celsius',
                'state': self.temperature,
                'device_class': SensorDeviceClass.TEMPERATURE,
                'unit': UnitOfTemperature.CELSIUS,
                "state_class": SensorStateClass.MEASUREMENT
            },
            'humidity': {
                'icon': 'mdi:water-percent',
                'state': self.humidity,
                'device_class': SensorDeviceClass.HUMIDITY,
                'unit': PERCENTAGE,
                "state_class": SensorStateClass.MEASUREMENT
            },
            'catLitterWeight': {
                'icon': 'mdi:home-percent-outline',
                'state': self.catLitterWeight,
                'unit': PERCENTAGE,
                "state_class": SensorStateClass.MEASUREMENT
            },
            'error': {
                'icon': 'mdi:alert-circle',
                'state': self.error,
                'state_attrs': self.error_attrs,
            },
            'last_log': {
                'icon': 'mdi:message',
                'state': self.last_log,
                'state_attrs': self.last_log_attrs,
            },
        }

    @property
    def hass_select(self):
        return {
            'mode': {
                'icon': 'mdi:menu',
                'options': list(self.modes.values()),
                'state_attrs': self.mode_attrs,
                'async_select': self.select_mode,
            },
            'action': {
                'icon': 'mdi:play-box',
                'options': list(self.actions.values()),
                'async_select': self.select_action,
                'delay_update': 5,
            },
        }


class CatlinkEntity(CoordinatorEntity):
    def __init__(self, entity_key: str, device: Device, option=None):
        self.coordinator = device.coordinator
        CoordinatorEntity.__init__(self, self.coordinator)
        self.account = self.coordinator.account
        self._entity_key = entity_key
        self._device = device
        self._device_id = device.id
        self._device_name = device.name

        self._unique_id = f'{self._device_id}-{entity_key}'
        mac = device.mac[-4:] if device.mac else device.id
        self.entity_id = f'{DOMAIN}.{device.type.lower()}_{mac}_{entity_key}'

        self._option = option or {}
        self._attr_unit_of_measurement = option.get("unit")
        self._attr_native_unit_of_measurement = option.get("unit")
        self._attr_state_class = option.get("state_class")
        self._attr_device_class = option.get("device_class")
        self._attr_icon = option.get("icon")
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            name=self._device.name,
            model=self._device.model,
            manufacturer='CatLink',
            sw_version=self._device.firmwareVersion,
        )

    @property
    def name(self):
        return f'{self._device.name} {self._entity_key}'.strip()

    @property
    def unique_id(self):
        return self._unique_id

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        self._device.listeners[self.entity_id] = self._handle_coordinator_update
        self._handle_coordinator_update()

    def _handle_coordinator_update(self):
        self.update()
        self.async_write_ha_state()

    def update(self):
        if hasattr(self._device, self._entity_key):
            self._attr_state = getattr(self._device, self._entity_key)
            _LOGGER.debug('Entity update: %s', [self.entity_id, self._entity_key, self._attr_state])

        fun = self._option.get('state_attrs')
        if callable(fun):
            self._attr_extra_state_attributes = fun()

    async def async_request_api(self, api, params=None, method='GET', **kwargs):
        throw = kwargs.pop('throw', None)
        rdt = await self.account.request(api, params, method, **kwargs)
        if throw:
            persistent_notification.create(
                self.hass,
                f'{rdt}',
                f'Request: {api}',
                f'{DOMAIN}-request',
            )
        return rdt


class CatlinkBinaryEntity(CatlinkEntity):
    def __init__(self, entity_key, device: Device, option=None):
        super().__init__(entity_key, device, option)
        self._attr_is_on = False

    def update(self):
        if hasattr(self._device, self._entity_key):
            self._attr_is_on = not not getattr(self._device, self._entity_key)
        else:
            self._attr_is_on = False
