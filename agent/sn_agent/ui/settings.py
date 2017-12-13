from sn_agent import SettingsBase, Required


class WebSettings(SettingsBase):
    def __init__(self, **custom_settings):
        self.STATIC_ROOT_URL = '/static'
        self.ETH_CLIENT = 'http://geth:8545'
        self._ENV_PREFIX = 'SN_WEB_'
        self.COOKIE_SECRET = 'S^L/<cJUd$"p$5kH' # Required(str)
        self._ENV_PREFIX = 'SN_WEB_'
        self.AUTH_REALM = 'SingularityNET'
        self.AUTH_SECRET = 'b_wy%h=ts0ii3g0ulqbx8q%w(72zh%4hslu7js&(^q+_s49jj-'
        self.AUTH_USERNAME = 'sn_user'
        self.AUTH_PASSWORD = '1234'
        super().__init__(**custom_settings)
