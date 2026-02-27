# 机器人接口使用文档

## 1. 功能介绍

本系统提供了机器人部署和管理的API接口，支持以下功能：

- 部署机器人（支持限流，防止滥用）
- 测试机器人
- 获取机器人列表
- 删除机器人

## 2. 机器人模板

系统目前提供以下机器人模板，存放在 `bot_model` 文件夹下：

### 2.1 你问我答机器人 (echo_bot)

- **功能**：简单重复用户输入的内容
- **配置**：无需特殊配置
- **使用场景**：测试基本功能

### 2.2 OpenAI API接入机器人 (openai_bot)

- **功能**：使用OpenAI API生成智能回复
- **配置**：需要提供OpenAI API密钥
- **使用场景**：智能对话、问答等

## 3. API接口说明

### 3.1 部署机器人

**接口**：`POST /deploy_bot`

**参数**：
- `name`：机器人名称（必填）
- `description`：机器人描述（可选）
- `template`：模板名称（必填，如echo_bot、openai_bot）
- `config`：配置信息（JSON格式，可选）

**返回**：
```json
{
  "success": true,
  "bot_id": "机器人ID"
}
```

**限流**：1分钟内最多部署2个机器人

**示例**：
```bash
# 部署你问我答机器人
curl -X POST http://localhost:5000/deploy_bot \
  -d "name=我的回声机器人" \
  -d "description=简单重复用户输入" \
  -d "template=echo_bot"

# 部署OpenAI机器人
curl -X POST http://localhost:5000/deploy_bot \
  -d "name=我的智能助手" \
  -d "description=使用OpenAI API" \
  -d "template=openai_bot" \
  -d "config={\"api_key\": \"your_openai_api_key\", \"model\": \"gpt-3.5-turbo\"}"
```

### 3.2 测试机器人

**接口**：`POST /test_bot`

**参数**：
- `bot_id`：机器人ID（必填）
- `message`：测试消息（必填）

**返回**：
```json
{
  "success": true,
  "response": "机器人回复"
}
```

**示例**：
```bash
curl -X POST http://localhost:5000/test_bot \
  -d "bot_id=机器人ID" \
  -d "message=你好，机器人"
```

### 3.3 获取机器人列表

**接口**：`GET /get_bots`

**返回**：
```json
{
  "success": true,
  "bots": [
    {
      "id": "机器人ID",
      "name": "机器人名称",
      "description": "机器人描述",
      "template": "模板名称",
      "created_at": 1234567890
    }
  ]
}
```

**示例**：
```bash
curl http://localhost:5000/get_bots
```

### 3.4 删除机器人

**接口**：`POST /delete_bot/<bot_id>`

**返回**：
```json
{
  "success": true
}
```

**示例**：
```bash
curl -X POST http://localhost:5000/delete_bot/机器人ID
```

## 4. 机器人模板使用指南

### 4.1 你问我答机器人 (echo_bot)

**配置**：无需特殊配置

**使用示例**：
1. 部署机器人：
   ```bash
   curl -X POST http://localhost:5000/deploy_bot \
     -d "name=回声机器人" \
     -d "template=echo_bot"
   ```

2. 测试机器人：
   ```bash
   curl -X POST http://localhost:5000/test_bot \
     -d "bot_id=机器人ID" \
     -d "message=你好"
   ```

3. 预期回复：
   ```
   你说: 你好
   ```

### 4.2 OpenAI API接入机器人 (openai_bot)

**配置**：
- `api_key`：OpenAI API密钥（必填）
- `model`：模型名称，默认gpt-3.5-turbo（可选）
- `max_tokens`：最大回复 tokens 数，默认150（可选）

**使用示例**：
1. 部署机器人：
   ```bash
   curl -X POST http://localhost:5000/deploy_bot \
     -d "name=智能助手" \
     -d "template=openai_bot" \
     -d "config={\"api_key\": \"your_openai_api_key\"}"
   ```

2. 测试机器人：
   ```bash
   curl -X POST http://localhost:5000/test_bot \
     -d "bot_id=机器人ID" \
     -d "message=什么是人工智能？"
   ```

3. 预期回复：
   ```
   人工智能（Artificial Intelligence，简称AI）是指由人制造出来的系统所表现出来的智能。它是计算机科学的一个分支，旨在创建能够模拟人类智能行为的机器。人工智能的研究包括机器学习、自然语言处理、计算机视觉、机器人技术等多个领域。
   ```

## 5. 注意事项

1. **限流**：部署机器人有频率限制，1分钟内最多部署2个机器人，避免系统滥用。

2. **安全**：OpenAI API密钥属于敏感信息，请妥善保管，不要在代码中硬编码。

3. **错误处理**：API接口会返回详细的错误信息，请根据错误信息调整请求参数。

4. **模板扩展**：如需添加新的机器人模板，只需在 `bot_model` 文件夹下创建新的Python文件，实现相应的类和方法即可。

## 6. 模板扩展指南

要创建自定义机器人模板，请按照以下步骤操作：

1. 在 `bot_model` 文件夹下创建新的Python文件，如 `custom_bot.py`

2. 实现一个类，类名与文件名保持一致（首字母大写）

3. 实现以下方法：
   - `__init__(self, config)`：初始化方法，接收配置参数
   - `process_message(self, message)`：处理消息的方法，返回回复
   - `get_info(self)`：获取机器人信息的方法

4. 部署机器人时，使用模板名称（文件名，不含.py后缀）

**示例**：
```python
# bot_model/custom_bot.py
class CustomBot:
    def __init__(self, config=None):
        self.config = config or {}
    
    def process_message(self, message):
        return f"自定义机器人回复: {message}"
    
    def get_info(self):
        return {
            "name": "自定义机器人",
            "description": "自定义机器人模板",
            "template": "custom_bot"
        }
```

部署自定义机器人：
```bash
curl -X POST http://localhost:5000/deploy_bot \
  -d "name=我的自定义机器人" \
  -d "template=custom_bot"
```
