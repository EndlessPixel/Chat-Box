"""你问我答机器人模板"""

class EchoBot:
    def __init__(self, config=None):
        """初始化机器人
        
        Args:
            config: 配置信息，可选
        """
        self.config = config or {}
    
    def process_message(self, message):
        """处理消息
        
        Args:
            message: 用户发送的消息
            
        Returns:
            str: 机器人的回复
        """
        # 简单地重复用户的消息
        return f"你说: {message}"
    
    def get_info(self):
        """获取机器人信息
        
        Returns:
            dict: 机器人信息
        """
        return {
            "name": "你问我答机器人",
            "description": "简单重复用户输入的内容",
            "template": "echo_bot"
        }
