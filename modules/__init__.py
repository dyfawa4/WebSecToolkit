from typing import Dict, Type, Callable
from PyQt6.QtWidgets import QWidget

_modules: Dict[str, Type[QWidget]] = {}


def register_module(module_id: str) -> Callable:
    def decorator(cls: Type[QWidget]) -> Type[QWidget]:
        _modules[module_id] = cls
        return cls
    return decorator


def get_module(module_id: str) -> Type[QWidget] | None:
    return _modules.get(module_id)


def get_module_widget(module_id: str) -> QWidget | None:
    module_class = _modules.get(module_id)
    if module_class:
        return module_class()
    return None


def get_all_modules() -> Dict[str, Type[QWidget]]:
    return _modules.copy()


def get_module_ids() -> list:
    return list(_modules.keys())


from .recon import (
    PortScannerWidget,
    SubdomainScannerWidget,
    DirectoryScannerWidget,
    FingerprintWidget,
    SSLAnalyzerWidget,
    EmailCollectorWidget,
)

from .web import (
    SQLiScannerWidget,
    XSSScannerWidget,
    LFIScannerWidget,
    RCEScannerWidget,
    SSRFScannerWidget,
    XXEScannerWidget,
)

from .vuln_scan import (
    BatchScanWidget,
    CVESearchWidget,
    PoCManagerWidget,
    ExploitSearchWidget,
)

from .password import (
    HashCrackerWidget,
    OnlineBruteWidget,
    PasswordGeneratorWidget,
)

from .proxy import (
    HTTPProxyWidget,
    TunnelWidget,
    ReverseProxyWidget,
)

from .internal import (
    InternalInfoWidget,
    CredentialWidget,
    LateralMovementWidget,
    PersistenceWidget,
    PrivilegeEscalationWidget,
)

from .payload import (
    PayloadGeneratorWidget,
    EncoderWidget,
    ExploitDBWidget,
)

from .web_adv import (
    SSTIScannerWidget,
    LFRIScannerWidget,
    CSRFScannerWidget,
    APISecurityWidget,
    FrameworkScannerWidget,
    AuthVulnScannerWidget,
    FileVulnScannerWidget,
    CacheVulnScannerWidget,
    HTTPSmugglingWidget,
    OpenRedirectWidget,
    ClickjackingWidget,
    BusinessLogicWidget,
    JWTSecurityWidget,
    SupplyChainWidget,
    PrototypePollutionWidget,
    CloudSecurityWidget,
    WebSocketWidget,
    AISecurityWidget,
)

from .internal_adv import (
    LateralMoveWidget,
    DomainAttackWidget,
    ADCSAttackWidget,
    EvasionWidget,
    ExchangeWidget,
    SharePointWidget,
)

from .payload_adv import (
    HashIdentifyWidget,
    DictGeneratorWidget,
    POCManagerWidget,
    ExploitSearchWidget,
    ReverseShellWidget,
    WebshellWidget,
    MSFPayloadWidget,
    PayloadEvasionWidget,
    PhishingFileWidget,
)

from .tools import (
    RequestBuilderWidget,
    RepeaterWidget,
    IntruderWidget,
    BaseEncoderWidget,
    URLEncoderWidget,
    HashCalcWidget,
    JWTEncoderWidget,
    CryptoWidget,
    ClassicCipherWidget,
)

from .ai_assistant import AIAssistantWidget

from .gen import (
    PasswordGenWidget,
    UsernameGenWidget,
    DirGenWidget,
    SubdomainGenWidget,
    DictManagerWidget,
    ReportGenWidget,
    ProjectManageWidget,
    DataExportWidget,
    VulnStatsWidget,
    HistoryWidget,
)

from .utils import (
    IPToolWidget,
    HTTPToolWidget,
    JSONToolWidget,
    RegexToolWidget,
    TimeToolWidget,
    DiffToolWidget,
)


__all__ = [
    'register_module',
    'get_module',
    'get_module_widget',
    'get_all_modules',
    'get_module_ids',
]
