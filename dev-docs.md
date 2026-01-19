# 开发者文档

## 技术栈

### 后端
- **框架**: Flask
- **ORM**: Flask-SQLAlchemy
- **数据库**: SQLite
- **认证**: Flask Session
- **密码加密**: SHA-512
- **用户名加密**: Base64

### 前端
- **HTML5**
- **CSS3**
- **JavaScript (ES6+)**
- **AJAX (XMLHttpRequest)**
- **图标库**: Font Awesome

### 开发工具
- **IDE**: VS Code
- **语言**: Python 3.8+
- **依赖管理**: Pip

## 项目结构

```
Chat_Box/
├── app.py              # 应用入口
├── extensions.py       # 扩展初始化（避免循环导入）
├── models.py           # 数据库模型
├── routes.py           # 路由定义
├── static/
│   └── styles.css      # 样式文件
├── templates/
│   ├── chat.html           # 主聊天页面
│   ├── chat_room.html      # 聊天室内页
│   ├── create_chat_room.html  # 创建聊天室
│   ├── edit_chat_room.html    # 编辑聊天室
│   ├── edit_profile.html     # 编辑个人资料
│   ├── login.html            # 登录页面
│   ├── manage_requests.html  # 审核请求
│   ├── register.html         # 注册页面
│   ├── search_chat_room.html # 搜索聊天室
│   └── search_user.html      # 搜索用户
└── chatbox.db          # SQLite数据库文件
```

## 数据库设计

### 主要表结构

1. **User** - 用户表
   - id: 唯一标识符（UUID）
   - username: 用户名（Base64加密）
   - password: 密码（SHA-512加密）
   - nickname: 昵称
   - bio: 个人简介
   - created_at: 创建时间
   - updated_at: 更新时间

2. **ChatRoom** - 聊天室表
   - id: 唯一标识符（UUID）
   - name: 聊天室名称
   - description: 聊天室简介
   - tags: 标签
   - creator_id: 创建者ID
   - created_at: 创建时间
   - updated_at: 更新时间

3. **ChatRoomMember** - 聊天室成员表
   - id: 唯一标识符
   - user_id: 用户ID
   - chat_room_id: 聊天室ID
   - role: 角色（owner, admin, member）
   - status: 状态（pending, approved）
   - joined_at: 加入时间

4. **Message** - 消息表
   - id: 唯一标识符（UUID）
   - sender_id: 发送者ID
   - chat_room_id: 聊天室ID
   - friend_id: 好友ID（私聊）
   - content: 消息内容
   - sent_at: 发送时间
   - is_recalled: 是否已撤回
   - reply_to: 回复的消息ID

5. **FriendRequest** - 好友请求表
   - id: 唯一标识符
   - sender_id: 发送者ID
   - receiver_id: 接收者ID
   - status: 状态（pending, accepted, rejected）
   - created_at: 创建时间

6. **Friendship** - 好友关系表
   - id: 唯一标识符
   - user1_id: 用户1ID
   - user2_id: 用户2ID
   - created_at: 创建时间

## 开发说明

### 扩展初始化

为了避免循环导入问题，应用使用了 `extensions.py` 文件来初始化 Flask 应用和 SQLAlchemy 实例：

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatbox.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
```

### 长轮询实现

应用使用长轮询技术实现实时消息更新，最长等待时间为25秒：

```python
while time.time() - start_time < 25:  # 最长等待25秒
    # 查询新消息
    if last_sent_at > 0:
        # 有最后一条消息的发送时间，查询比它新的消息
        messages = Message.query.filter(
            Message.chat_room_id == room_id,
            Message.sent_at > last_sent_at
        ).order_by(Message.sent_at).all()
    else:
        # 没有最后一条消息，查询最新的10条消息
        messages = Message.query.filter_by(
            chat_room_id=room_id
        ).order_by(Message.sent_at.desc()).limit(10).all()
        messages.reverse()  # 反转顺序，使最早的消息在最上面
    
    if messages:
        # 返回新消息
        break
    
    # 没有新消息，等待1秒
    time.sleep(1)
```

长轮询工作原理：
1. 客户端发送请求，包含最后一条消息的ID
2. 服务器查询比该消息更新的消息
3. 如果有新消息，立即返回
4. 如果没有新消息，服务器等待1秒后再次查询
5. 重复步骤3-4，直到超时(25秒)或有新消息
6. 客户端收到响应后，立即发送新的请求

这种方式比传统的轮询更高效，减少了不必要的网络请求，同时保持了实时性。

### 自定义提示组件

应用使用自定义的提示组件替代浏览器默认的 `alert()` 和 `confirm()`：

- **Toast**: 左下角弹出，自动消失
- **Confirm**: 底部居中显示，包含确认和取消按钮
- **支持多种类型**: 成功、错误、信息、警告

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

如有问题或建议，欢迎通过以下方式联系：

- 项目地址: https://github.com/En'd'less'P/chatbox
- 邮箱: your.email@example.com

---

**最后更新**: 2026-01-19
**版本**: v1.0.1