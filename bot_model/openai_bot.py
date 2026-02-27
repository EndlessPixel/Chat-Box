"""OpenAI API接入机器人模板"""
import openai

class OpenAIBot:
    def __init__(self, config):
        """初始化机器人
        
        Args:
            config: 配置信息，必须包含api_key
        """
        self.config = config
        if 'api_key' not in config:
            raise ValueError("OpenAIBot requires api_key in config")
        openai.api_key = config['api_key']
        self.model = config.get('model', 'gpt-3.5-turbo')
        self.max_tokens = config.get('max_tokens', 150)
    
    def process_message(self, message):
        """处理消息
        
        Args:
            message: 用户发送的消息
            
        Returns:
            str: 机器人的回复
        """
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个智能助手"},
                    {"role": "user", "content": message}
                ],
                max_tokens=self.max_tokens
            )
            return response['choices'][0]['message']['content'].strip()
        except Exception as e:
            return f"抱歉，处理消息时出错: {str(e)}"
    
    def get_info(self):
        """获取机器人信息
        
        Returns:
            dict: 机器人信息
        """
        return {
            "name": "OpenAI智能助手",
            "description": "使用OpenAI API生成回复",
            "template": "openai_bot"
        }
