from extensions import db
import uuid
import time

# 用户表
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    nickname = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, default=lambda: int(time.time()), onupdate=lambda: int(time.time()))
    
    def __repr__(self):
        return f'<User {self.username}>'

# 聊天室表
class ChatRoom(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(256), nullable=True)
    creator_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, default=lambda: int(time.time()), onupdate=lambda: int(time.time()))
    
    def __repr__(self):
        return f'<ChatRoom {self.name}>'

# 聊天室成员表
class ChatRoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    chat_room_id = db.Column(db.String(36), db.ForeignKey('chat_room.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')  # member, admin, owner
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved
    joined_at = db.Column(db.Integer, default=lambda: int(time.time()))
    
    def __repr__(self):
        return f'<ChatRoomMember user={self.user_id} room={self.chat_room_id}>'

# 聊天消息表
class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    chat_room_id = db.Column(db.String(36), db.ForeignKey('chat_room.id'), nullable=True)
    friend_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.Integer, default=lambda: int(time.time()))
    is_撤回 = db.Column(db.Boolean, default=False)
    reply_to = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=True)
    
    def __repr__(self):
        return f'<Message {self.id}>'

# 好友请求表
class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    
    def __repr__(self):
        return f'<FriendRequest {self.sender_id} -> {self.receiver_id}>'

# 好友关系表
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user1_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    
    def __repr__(self):
        return f'<Friendship {self.user1_id} & {self.user2_id}>'
