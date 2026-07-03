"""
===============================================================================
                    OffSec AI-300 多平台配置加载器
===============================================================================
功能: 根据 .env 文件中的 PLATFORM_SELECTOR 自动加载对应平台的配置
支持平台列表:
  国内平台: ZHIPU, QWEN, BAIDU, DEEPSEEK
  国外主流: OPENAI, ANTHROPIC, AZURE_OPENAI, AWS_BEDROCK, GOOGLE_GEMINI
  开源本地: OLLAMA, HUGGINGFACE
  欧洲平台: COHERE, MISTRAL, VOYAGE, PERPLEXITY
  Meta平台: META_LLAMA
使用方法: 
    from platform_config_loader import load_platform_config
    load_platform_config()
===============================================================================
"""

import os
import re
from dotenv import load_dotenv

# 平台分类
PLATFORM_CATEGORIES = {
    "国内平台": ["ZHIPU", "QWEN", "BAIDU", "DEEPSEEK"],
    "国外主流": ["OPENAI", "ANTHROPIC", "AZURE_OPENAI", "AWS_BEDROCK", "GOOGLE_GEMINI"],
    "开源本地": ["OLLAMA", "HUGGINGFACE"],
    "欧洲平台": ["COHERE", "MISTRAL", "VOYAGE", "PERPLEXITY"],
    "Meta平台": ["META_LLAMA"],
}

# OpenAI兼容平台（使用OPENAI_CHAT_ENDPOINT/KEY/MODEL）
OPENAI_COMPATIBLE_PLATFORMS = [
    "ZHIPU", "QWEN", "DEEPSEEK", "OPENAI", "AZURE_OPENAI",
    "OLLAMA", "HUGGINGFACE", "MISTRAL", "PERPLEXITY", "META_LLAMA"
]

def find_project_root():
    """
    从当前文件路径向上查找项目根目录（包含 .env 文件的目录）
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    while current_dir:
        env_path = os.path.join(current_dir, '.env')
        if os.path.exists(env_path):
            return current_dir
        
        parent_dir = os.path.dirname(current_dir)
        if parent_dir == current_dir:
            break
        current_dir = parent_dir
    
    return os.path.dirname(os.path.abspath(__file__))

def load_platform_config():
    """
    根据 PLATFORM_SELECTOR 加载对应平台的配置到环境变量
    """
    # 查找项目根目录
    project_root = find_project_root()
    
    # 配置文件路径
    env_path = os.path.join(project_root, '.env')
    
    if not os.path.exists(env_path):
        print(f"❌ 配置文件不存在: {env_path}")
        return
    
    # 加载 .env 文件
    load_dotenv(env_path)
    
    # 获取当前选择的平台
    platform = os.getenv("PLATFORM_SELECTOR", "ZHIPU").strip().upper()
    
    print(f"📤 正在加载平台配置: {platform}")
    
    # 手动解析 .env 文件，支持 [SECTION] 格式
    with open(env_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    current_section = None
    platform_config = {}
    
    for line in lines:
        line = line.strip()
        
        # 跳过空行和注释
        if not line or line.startswith('#'):
            continue
        
        # 匹配 section 标题 [SECTION]
        section_match = re.match(r'^\[(\w+)\]$', line)
        if section_match:
            current_section = section_match.group(1)
            continue
        
        # 匹配 key=value
        key_value_match = re.match(r'^(\w+)\s*=\s*(.+)$', line)
        if key_value_match and current_section:
            key = key_value_match.group(1)
            value = key_value_match.group(2)
            
            # 如果是当前平台，保存配置
            if current_section == platform:
                platform_config[key] = value
    
    if not platform_config:
        print(f"❌ 平台配置不存在: {platform}")
        print_platform_list()
        return
    
    # 加载平台配置到环境变量
    for key, value in platform_config.items():
        os.environ[key] = value
        masked_value = '***' + value[-4:] if len(value) > 4 else '***'
        print(f"   {key}: {masked_value if 'KEY' in key or 'SECRET' in key else value}")
    
    # 特殊平台处理
    handle_special_platforms(platform)
    
    print(f"✅ 平台配置加载完成: {platform}\n")

def handle_special_platforms(platform):
    """
    处理特殊平台的配置转换
    """
    if platform == "BAIDU":
        # 百度需要将API_KEY和SECRET_KEY组合成Authorization
        api_key = os.getenv("OPENAI_CHAT_KEY")
        secret_key = os.getenv("BAIDU_SECRET_KEY")
        if api_key and secret_key:
            os.environ["BAIDU_AUTH"] = f"{api_key}:{secret_key}"
    
    elif platform == "ANTHROPIC":
        # Anthropic使用独立的环境变量名
        api_key = os.getenv("ANTHROPIC_API_KEY")
        model = os.getenv("ANTHROPIC_MODEL")
        if api_key and model:
            print("   提示: Anthropic使用独立的API格式，需要单独安装anthropic库")
    
    elif platform == "AWS_BEDROCK":
        # AWS Bedrock需要配置boto3
        access_key = os.getenv("BEDROCK_ACCESS_KEY")
        secret_key = os.getenv("BEDROCK_SECRET_KEY")
        region = os.getenv("BEDROCK_REGION")
        if access_key and secret_key and region:
            os.environ["AWS_ACCESS_KEY_ID"] = access_key
            os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
            os.environ["AWS_DEFAULT_REGION"] = region
            print("   提示: AWS Bedrock需要安装boto3库并配置AWS凭证")
    
    elif platform == "GOOGLE_GEMINI":
        # Google Gemini使用独立的环境变量名
        api_key = os.getenv("GEMINI_API_KEY")
        model = os.getenv("GEMINI_MODEL")
        if api_key and model:
            print("   提示: Google Gemini需要安装google-generativeai库")
    
    elif platform == "COHERE":
        # Cohere使用独立的环境变量名
        api_key = os.getenv("COHERE_API_KEY")
        model = os.getenv("COHERE_MODEL")
        if api_key and model:
            print("   提示: Cohere需要安装cohere库")
    
    elif platform == "VOYAGE":
        # Voyage使用独立的环境变量名
        api_key = os.getenv("VOYAGE_API_KEY")
        model = os.getenv("VOYAGE_MODEL")
        if api_key and model:
            print("   提示: Voyage需要安装voyageai库")

def print_platform_list():
    """
    打印支持的平台列表
    """
    print("\n📋 支持的平台列表:")
    for category, platforms in PLATFORM_CATEGORIES.items():
        print(f"\n  {category}:")
        for p in platforms:
            print(f"    - {p}")
    print("\n请在 .env 文件中设置 PLATFORM_SELECTOR=平台名称")

if __name__ == "__main__":
    load_platform_config()
