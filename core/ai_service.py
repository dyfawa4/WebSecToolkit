import json
import asyncio
import aiohttp
import requests
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from queue import Queue
import time


class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    CUSTOM = "custom"


@dataclass
class AIMessage:
    role: str
    content: str
    
    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class AIRequest:
    messages: List[AIMessage]
    model: str = ""
    temperature: float = 0.7
    max_tokens: int = 4096
    stream: bool = False
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIResponse:
    success: bool
    content: str = ""
    error: str = ""
    usage: Dict[str, int] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)


class BaseAIProvider(ABC):
    def __init__(self, api_key: str, base_url: str = "", **kwargs):
        self.api_key = api_key
        self.base_url = base_url
        self.config = kwargs
    
    @abstractmethod
    def chat(self, request: AIRequest) -> AIResponse:
        pass
    
    @abstractmethod
    async def chat_async(self, request: AIRequest) -> AIResponse:
        pass
    
    @abstractmethod
    def stream_chat(self, request: AIRequest, callback: Callable[[str], None]) -> AIResponse:
        pass
    
    def _build_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }


class OpenAICompatibleProvider(BaseAIProvider):
    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1", **kwargs):
        super().__init__(api_key, base_url, **kwargs)
        self.default_model = kwargs.get("model", "gpt-3.5-turbo")
    
    def chat(self, request: AIRequest) -> AIResponse:
        if not request.model:
            request.model = self.default_model
        
        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        
        payload = {
            "model": request.model,
            "messages": [m.to_dict() for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": False,
            **request.extra_params
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            
            return AIResponse(
                success=True,
                content=content,
                usage=usage,
                raw_response=data
            )
        except requests.exceptions.Timeout:
            return AIResponse(success=False, error="请求超时")
        except requests.exceptions.RequestException as e:
            return AIResponse(success=False, error=f"请求失败: {str(e)}")
        except Exception as e:
            return AIResponse(success=False, error=f"未知错误: {str(e)}")
    
    async def chat_async(self, request: AIRequest) -> AIResponse:
        if not request.model:
            request.model = self.default_model
        
        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        
        payload = {
            "model": request.model,
            "messages": [m.to_dict() for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": False,
            **request.extra_params
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload, timeout=60) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        return AIResponse(success=False, error=f"HTTP {response.status}: {error_text}")
                    
                    data = await response.json()
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    usage = data.get("usage", {})
                    
                    return AIResponse(
                        success=True,
                        content=content,
                        usage=usage,
                        raw_response=data
                    )
        except asyncio.TimeoutError:
            return AIResponse(success=False, error="异步请求超时")
        except Exception as e:
            return AIResponse(success=False, error=f"异步请求失败: {str(e)}")
    
    def stream_chat(self, request: AIRequest, callback: Callable[[str], None]) -> AIResponse:
        if not request.model:
            request.model = self.default_model
        
        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        
        payload = {
            "model": request.model,
            "messages": [m.to_dict() for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": True,
            **request.extra_params
        }
        
        full_content = ""
        usage = {}
        
        try:
            response = requests.post(url, headers=headers, json=payload, stream=True, timeout=120)
            response.raise_for_status()
            
            for line in response.iter_lines():
                if not line:
                    continue
                
                line_text = line.decode("utf-8")
                if line_text.startswith("data: "):
                    data_str = line_text[6:]
                    if data_str == "[DONE]":
                        break
                    
                    try:
                        data = json.loads(data_str)
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        content_chunk = delta.get("content", "")
                        
                        if content_chunk:
                            full_content += content_chunk
                            if callback:
                                callback(content_chunk)
                    except json.JSONDecodeError:
                        continue
            
            return AIResponse(
                success=True,
                content=full_content,
                usage=usage,
                raw_response={}
            )
        except Exception as e:
            return AIResponse(success=False, error=f"流式请求失败: {str(e)}")


class AnthropicProvider(BaseAIProvider):
    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com/v1", **kwargs):
        super().__init__(api_key, base_url, **kwargs)
        self.default_model = kwargs.get("model", "claude-3-sonnet-20240229")
    
    def _build_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
    
    def chat(self, request: AIRequest) -> AIResponse:
        if not request.model:
            request.model = self.default_model
        
        url = f"{self.base_url}/messages"
        headers = self._build_headers()
        
        system_message = ""
        chat_messages = []
        for m in request.messages:
            if m.role == "system":
                system_message = m.content
            else:
                chat_messages.append(m.to_dict())
        
        payload = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": chat_messages,
            **request.extra_params
        }
        
        if system_message:
            payload["system"] = system_message
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            data = response.json()
            
            content = data.get("content", [{}])[0].get("text", "")
            usage = {
                "input_tokens": data.get("usage", {}).get("input_tokens", 0),
                "output_tokens": data.get("usage", {}).get("output_tokens", 0)
            }
            
            return AIResponse(
                success=True,
                content=content,
                usage=usage,
                raw_response=data
            )
        except Exception as e:
            return AIResponse(success=False, error=f"Anthropic请求失败: {str(e)}")
    
    async def chat_async(self, request: AIRequest) -> AIResponse:
        return self.chat(request)
    
    def stream_chat(self, request: AIRequest, callback: Callable[[str], None]) -> AIResponse:
        return self.chat(request)


class DeepSeekProvider(OpenAICompatibleProvider):
    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, "https://api.deepseek.com/v1", **kwargs)
        self.default_model = kwargs.get("model", "deepseek-chat")


class QwenProvider(OpenAICompatibleProvider):
    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, "https://dashscope.aliyuncs.com/compatible-mode/v1", **kwargs)
        self.default_model = kwargs.get("model", "qwen-turbo")


class AIServiceManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._providers: Dict[str, BaseAIProvider] = {}
        self._default_provider: Optional[str] = None
        self._config: Dict[str, Any] = {}
        self._operation_history: List[Dict[str, Any]] = []
        self._analysis_queue: Queue = Queue()
        self._callbacks: Dict[str, List[Callable]] = {}
    
    def configure(self, config: Dict[str, Any]) -> None:
        self._config = config
        
        providers_config = config.get("providers", {})
        for name, provider_config in providers_config.items():
            self.add_provider(name, provider_config)
        
        default_name = config.get("default_provider")
        if default_name and default_name in self._providers:
            self._default_provider = default_name
    
    def add_provider(self, name: str, config: Dict[str, Any]) -> bool:
        provider_type = config.get("type", "openai").lower()
        api_key = config.get("api_key", "")
        base_url = config.get("base_url", "")
        model = config.get("model", "")
        
        if not api_key:
            return False
        
        provider_map = {
            "openai": OpenAICompatibleProvider,
            "anthropic": AnthropicProvider,
            "deepseek": DeepSeekProvider,
            "qwen": QwenProvider,
        }
        
        provider_class = provider_map.get(provider_type, OpenAICompatibleProvider)
        
        kwargs = {"model": model} if model else {}
        if base_url:
            kwargs["base_url"] = base_url
        
        try:
            self._providers[name] = provider_class(api_key, **kwargs)
            if self._default_provider is None:
                self._default_provider = name
            return True
        except Exception:
            return False
    
    def remove_provider(self, name: str) -> bool:
        if name in self._providers:
            del self._providers[name]
            if self._default_provider == name:
                self._default_provider = next(iter(self._providers), None)
            return True
        return False
    
    def get_provider(self, name: Optional[str] = None) -> Optional[BaseAIProvider]:
        provider_name = name or self._default_provider
        if provider_name and provider_name in self._providers:
            return self._providers[provider_name]
        return None
    
    def list_providers(self) -> List[str]:
        return list(self._providers.keys())
    
    def chat(self, messages: List[AIMessage], provider: Optional[str] = None, **kwargs) -> AIResponse:
        ai_provider = self.get_provider(provider)
        if not ai_provider:
            return AIResponse(success=False, error="未配置AI服务提供商")
        
        request = AIRequest(messages=messages, **kwargs)
        return ai_provider.chat(request)
    
    async def chat_async(self, messages: List[AIMessage], provider: Optional[str] = None, **kwargs) -> AIResponse:
        ai_provider = self.get_provider(provider)
        if not ai_provider:
            return AIResponse(success=False, error="未配置AI服务提供商")
        
        request = AIRequest(messages=messages, **kwargs)
        return await ai_provider.chat_async(request)
    
    def stream_chat(self, messages: List[AIMessage], callback: Callable[[str], None], 
                    provider: Optional[str] = None, **kwargs) -> AIResponse:
        ai_provider = self.get_provider(provider)
        if not ai_provider:
            return AIResponse(success=False, error="未配置AI服务提供商")
        
        request = AIRequest(messages=messages, **kwargs)
        return ai_provider.stream_chat(request, callback)
    
    def record_operation(self, operation: Dict[str, Any]) -> None:
        operation["timestamp"] = time.time()
        self._operation_history.append(operation)
        
        if len(self._operation_history) > 1000:
            self._operation_history = self._operation_history[-500:]
        
        self._emit_event("operation_recorded", operation)
    
    def get_operation_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._operation_history[-limit:]
    
    def analyze_operation(self, operation: Dict[str, Any]) -> str:
        provider = self.get_provider()
        if not provider:
            return "AI服务未配置，无法分析操作"
        
        system_prompt = """你是一个网络安全工具箱的智能助手。用户正在使用各种安全测试工具。
请根据用户的操作提供专业的建议和提示。回复要简洁、专业、有帮助。"""

        user_prompt = f"""用户操作信息：
模块: {operation.get('module', '未知')}
操作: {operation.get('action', '未知')}
参数: {json.dumps(operation.get('params', {}), ensure_ascii=False)}
结果: {operation.get('result', '无')[:500]}

请分析这个操作并提供相关建议。"""

        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=user_prompt)
        ]
        
        response = self.chat(messages, max_tokens=500)
        return response.content if response.success else f"分析失败: {response.error}"
    
    def analyze_result(self, result_data: Dict[str, Any], context: Optional[str] = None) -> str:
        provider = self.get_provider()
        if not provider:
            return "AI服务未配置，无法分析结果"
        
        system_prompt = """你是一个网络安全分析专家。请对提供的安全测试结果进行专业分析。
分析应包括：
1. 发现的问题或漏洞
2. 潜在的安全风险
3. 建议的修复措施
4. 进一步测试建议

请用简洁专业的语言回答。"""

        result_text = json.dumps(result_data, ensure_ascii=False, indent=2)[:3000]
        
        user_prompt = f"""请分析以下安全测试结果：
{result_text}

{f'上下文信息: {context}' if context else ''}"""

        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=user_prompt)
        ]
        
        response = self.chat(messages, max_tokens=1000)
        return response.content if response.success else f"分析失败: {response.error}"
    
    def generate_questions(self, module: str, action: str, params: Dict[str, Any]) -> List[str]:
        provider = self.get_provider()
        if not provider:
            return ["AI服务未配置"]
        
        system_prompt = """你是一个安全测试助手。根据用户即将进行的操作，生成2-3个相关问题或建议。
问题应该帮助用户：
1. 确认操作参数是否正确
2. 提醒可能的注意事项
3. 建议相关的测试方法

每个问题一行，简洁明了。"""

        user_prompt = f"""用户即将执行：
模块: {module}
操作: {action}
参数: {json.dumps(params, ensure_ascii=False)}

请生成相关问题或建议："""

        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=user_prompt)
        ]
        
        response = self.chat(messages, max_tokens=300)
        
        if response.success:
            questions = [q.strip() for q in response.content.split('\n') if q.strip()]
            return questions[:3]
        return [f"生成问题失败: {response.error}"]
    
    def register_callback(self, event: str, callback: Callable) -> None:
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)
    
    def unregister_callback(self, event: str, callback: Callable) -> None:
        if event in self._callbacks:
            if callback in self._callbacks[event]:
                self._callbacks[event].remove(callback)
    
    def _emit_event(self, event: str, data: Any) -> None:
        if event in self._callbacks:
            for callback in self._callbacks[event]:
                try:
                    callback(data)
                except Exception:
                    pass
    
    def is_configured(self) -> bool:
        return len(self._providers) > 0
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "configured": self.is_configured(),
            "providers": self.list_providers(),
            "default_provider": self._default_provider,
            "operation_count": len(self._operation_history)
        }


class OperationAnalyzer:
    def __init__(self, ai_manager: AIServiceManager):
        self.ai_manager = ai_manager
        self._analysis_templates: Dict[str, str] = {
            "port_scanner": "端口扫描分析：检查发现的开放端口是否存在安全风险",
            "subdomain": "子域名枚举分析：评估子域名暴露面和潜在风险",
            "vuln_scan": "漏洞扫描分析：分析发现的漏洞及其严重程度",
            "sqli": "SQL注入分析：评估注入漏洞的可利用性和修复建议",
            "hash_crack": "哈希破解分析：评估密码强度和安全建议"
        }
    
    def analyze(self, module: str, operation: Dict[str, Any], result: Any) -> Dict[str, Any]:
        analysis = {
            "module": module,
            "operation": operation,
            "timestamp": time.time(),
            "ai_analysis": None,
            "recommendations": []
        }
        
        if not self.ai_manager.is_configured():
            analysis["ai_analysis"] = "AI服务未配置"
            return analysis
        
        template = self._analysis_templates.get(module, "安全测试结果分析")
        
        result_data = {
            "module": module,
            "operation": operation,
            "result": result,
            "analysis_type": template
        }
        
        analysis["ai_analysis"] = self.ai_manager.analyze_result(result_data)
        
        return analysis


class ResultReporter:
    def __init__(self, ai_manager: AIServiceManager):
        self.ai_manager = ai_manager
        self._report_templates: Dict[str, str] = {}
    
    def generate_report(self, analysis_data: Dict[str, Any], format: str = "text") -> str:
        if format == "json":
            return json.dumps(analysis_data, ensure_ascii=False, indent=2)
        
        report_lines = [
            "=" * 50,
            "安全测试分析报告",
            "=" * 50,
            "",
            f"模块: {analysis_data.get('module', '未知')}",
            f"时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(analysis_data.get('timestamp', time.time())))}",
            "",
            "AI分析结果:",
            "-" * 40,
            analysis_data.get("ai_analysis", "无分析结果"),
            "",
        ]
        
        recommendations = analysis_data.get("recommendations", [])
        if recommendations:
            report_lines.extend([
                "建议:",
                "-" * 40,
            ])
            for i, rec in enumerate(recommendations, 1):
                report_lines.append(f"{i}. {rec}")
        
        return "\n".join(report_lines)


ai_service_manager = AIServiceManager()
operation_analyzer = OperationAnalyzer(ai_service_manager)
result_reporter = ResultReporter(ai_service_manager)
