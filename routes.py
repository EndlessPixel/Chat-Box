from extensions import app, db, socketio
from models import *
from flask import render_template, request, redirect, url_for, session, jsonify
from flask_socketio import emit, join_room, leave_room, disconnect
import base64
import hashlib
import uuid
import time
import Levenshtein
from collections import deque

# 存储用户消息记录，key为user_id，value为deque([(time, content), ...])
user_message_records = {}
# 最大消息记录数
MAX_MESSAGE_RECORDS = 5
# 频率限制：1秒内最多3条消息
FREQUENCY_LIMIT = 3
FREQUENCY_WINDOW = 1  # 秒
# 重复度限制：80%相似度
SIMILARITY_THRESHOLD = 0.8

# 辅助函数
def hash_password(password):
    return hashlib.sha512(password.encode()).hexdigest()

# 检查消息频率和重复度
def check_message_spam(user_id, content):
    """
    检查用户消息是否违反频率限制和重复度限制
    :param user_id: 用户ID
    :param content: 消息内容
    :return: (是否允许发送, 错误信息)
    """
    current_time = time.time()
    
    # 初始化用户消息记录
    if user_id not in user_message_records:
        user_message_records[user_id] = deque(maxlen=MAX_MESSAGE_RECORDS)
    
    message_deque = user_message_records[user_id]
    
    # 1. 检查频率限制：1秒内最多3条消息
    recent_messages = [msg for msg in message_deque if current_time - msg[0] < FREQUENCY_WINDOW]
    if len(recent_messages) >= FREQUENCY_LIMIT:
        return False, "发送频率过快，请稍后再试"
    
    # 2. 检查重复度限制：连续3条消息80%以上相似
    if len(message_deque) >= 2:  # 需要至少2条历史消息来比较
        # 获取最近3条消息（包括当前消息）
        recent_3 = list(message_deque)[-2:] + [(current_time, content)]
        
        # 计算相似度
        all_similar = True
        for i in range(1, len(recent_3)):
            prev_content = recent_3[i-1][1]
            curr_content = recent_3[i][1]
            
            # 计算Levenshtein相似度
            if not prev_content or not curr_content:
                continue
            
            # 计算编辑距离
            distance = Levenshtein.distance(prev_content, curr_content)
            max_len = max(len(prev_content), len(curr_content))
            similarity = 1 - (distance / max_len) if max_len > 0 else 1
            
            if similarity < SIMILARITY_THRESHOLD:
                all_similar = False
                break
        
        if all_similar:
            return False, "消息内容重复度过高，请发送不同内容"
    
    # 允许发送，更新消息记录
    message_deque.append((current_time, content))
    return True, ""

def encode_username(username):
    return base64.b64encode(username.encode()).decode()

def decode_username(encoded_username):
    return base64.b64decode(encoded_username.encode()).decode()

def format_time(timestamp):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

def validate_password(password):
    # 检查密码长度至少8位
    if len(password) < 8:
        return False, '密码长度至少8位'
    # 检查包含字母
    if not any(c.isalpha() for c in password):
        return False, '密码必须包含字母'
    # 检查包含数字
    if not any(c.isdigit() for c in password):
        return False, '密码必须包含数字'
    return True, '密码符合要求'

# 链接处理函数
def process_links(content):
    """
    处理消息中的链接，只允许合法的<a>标签和href属性
    :param content: 消息内容
    :return: 处理后的内容
    """
    import re
    
    # 定义允许的链接正则表达式
    allowed_url_pattern = r'^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/\S*)?$'
    
    # 处理<a>标签，只保留href属性，且href必须是合法的http/https链接
    def replace_link(match):
        full_tag = match.group(0)
        href_match = re.search(r'href=["\']([^"\']+)["\']', full_tag)
        if href_match:
            href = href_match.group(1)
            # 检查href是否是合法的http/https链接
            if re.match(allowed_url_pattern, href):
                # 获取链接文本
                text_match = re.search(r'>(.*?)<\/a>', full_tag, re.DOTALL)
                link_text = text_match.group(1) if text_match else ''
                # 只保留href属性，重新构建<a>标签
                return f'<a href="{href}">{link_text}</a>'
        # 非法链接，直接返回链接文本
        text_match = re.search(r'>(.*?)<\/a>', full_tag, re.DOTALL)
        if text_match:
            return text_match.group(1)
        return full_tag
    
    # 替换所有<a>标签
    processed_content = re.sub(r'<a[^>]*>(.*?)<\/a>', replace_link, content, flags=re.DOTALL)
    return processed_content

# 违禁词处理函数
def process_forbidden_words(content, room_id):
    """
    处理违禁词
    :param content: 消息内容
    :param room_id: 聊天室ID
    :return: (处理后的内容, 是否允许发送)
    """
    # 获取当前聊天室的违禁词列表
    forbidden_words = ForbiddenWord.query.filter_by(
        chat_room_id=room_id
    ).all()
    
    if not forbidden_words:
        return content, True
    
    processed_content = content
    
    # 检查链接文本中的违禁词
    link_setting = ChatRoomLinkSetting.query.filter_by(chat_room_id=room_id).first()
    check_link_text = link_setting.check_link_text if link_setting else True
    
    if check_link_text:
        # 直接检查所有内容，包括链接文本
        for word in forbidden_words:
            if word.word in processed_content:
                if word.action == 'block':
                    # 禁止发送
                    return content, False
                elif word.action == 'mask':
                    # 自动打码，用*替换违禁词
                    mask = '*' * len(word.word)
                    processed_content = processed_content.replace(word.word, mask)
    else:
        # 只检查非链接文本中的违禁词
        import re
        
        # 保存所有链接
        links = re.findall(r'<a[^>]*>(.*?)<\/a>', processed_content, flags=re.DOTALL)
        link_placeholders = [f'__LINK_PLACEHOLDER_{i}__' for i in range(len(links))]
        
        # 替换链接为占位符
        for i, link in enumerate(links):
            processed_content = processed_content.replace(f'<a href="{re.search(r"href=[\"\']([^\"\']+)[\"\']", link).group(1)}">{link.split(">").pop().split("<")[0]}</a>', link_placeholders[i])
        
        # 处理违禁词
        for word in forbidden_words:
            if word.word in processed_content:
                if word.action == 'block':
                    # 禁止发送
                    return content, False
                elif word.action == 'mask':
                    # 自动打码，用*替换违禁词
                    mask = '*' * len(word.word)
                    processed_content = processed_content.replace(word.word, mask)
        
        # 恢复链接
        for i, placeholder in enumerate(link_placeholders):
            processed_content = processed_content.replace(placeholder, links[i])
    
    return processed_content, True

# 注意：使用lru_cache时，参数必须是可哈希类型，且缓存会在应用重启时清空
def get_user_chat_rooms(user_id):
    # 获取当前用户的聊天室列表
    return ChatRoom.query.join(ChatRoomMember).filter(
        ChatRoomMember.user_id == user_id,
        ChatRoomMember.status == 'approved'
    ).all()

# 主页
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 查找用户
        encoded_username = encode_username(username)
        user = User.query.filter_by(username=encoded_username).first()
        
        if user and user.password == hash_password(password):
            session['user_id'] = user.id
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

# 注册页面
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # 验证密码是否一致
        if password != confirm_password:
            return render_template('register.html', error='两次输入的密码不一致')
        
        # 验证密码
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return render_template('register.html', error=error_msg)
        
        # 检查用户名是否已存在
        encoded_username = encode_username(username)
        existing_user = User.query.filter_by(username=encoded_username).first()
        
        if existing_user:
            return render_template('register.html', error='用户名已存在')
        
        # 创建新用户
        new_user = User(
            username=encoded_username,
            password=hash_password(password),
            nickname=username
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# 聊天页面
@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    chat_rooms = ChatRoom.query.join(ChatRoomMember).filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.status == 'approved'
    ).all()
    
    return render_template('chat.html', user=user, chat_rooms=chat_rooms)

# 登出
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# 创建聊天室
@app.route('/create_chat_room', methods=['GET', 'POST'])
def create_chat_room():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        tags = request.form.get('tags', '')
        
        # 创建聊天室
        new_room = ChatRoom(
            name=name,
            description=description,
            tags=tags,
            creator_id=session['user_id']
        )
        
        db.session.add(new_room)
        db.session.commit()
        
        # 添加创建者为房间所有者
        member = ChatRoomMember(
            user_id=session['user_id'],
            chat_room_id=new_room.id,
            role='owner',
            status='approved'
        )
        
        db.session.add(member)
        db.session.commit()
        
        return redirect(url_for('chat'))
    
    return render_template('create_chat_room.html', chat_rooms=chat_rooms)

# 编辑聊天室
@app.route('/edit_chat_room/<room_id>', methods=['GET', 'POST'])
def edit_chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    room = ChatRoom.query.get(room_id)
    if not room:
        return redirect(url_for('chat'))
    
    # 检查是否为创建者
    member = ChatRoomMember.query.filter_by(
        user_id=session['user_id'],
        chat_room_id=room_id,
        role='owner'
    ).first()
    
    if not member:
        return redirect(url_for('chat'))
    
    if request.method == 'POST':
        room.name = request.form['name']
        room.description = request.form.get('description', '')
        room.tags = request.form.get('tags', '')
        
        db.session.commit()
        return redirect(url_for('chat'))
    
    return render_template('edit_chat_room.html', room=room, chat_rooms=chat_rooms)

# 审核请求页面
@app.route('/manage_requests')
def manage_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    # 获取当前用户管理的聊天室（所有者或管理员）
    managed_rooms = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).all()
    
    # 只有管理员或所有者才能访问此页面
    if not managed_rooms:
        return redirect(url_for('chat'))
    
    # 获取所有待审核请求
    pending_chat_requests = {}
    room_names = {}
    
    for managed in managed_rooms:
        room = ChatRoom.query.get(managed.chat_room_id)
        if not room:
            continue
        
        room_names[room.id] = room.name
        
        # 获取该聊天室的待审核请求，排除自己的请求
        requests = ChatRoomMember.query.filter(
            ChatRoomMember.chat_room_id == room.id,
            ChatRoomMember.status == 'pending',
            ChatRoomMember.user_id != session['user_id']
        ).all()
        
        if requests:
            # 格式化请求数据
            formatted_requests = []
            for req in requests:
                user = User.query.get(req.user_id)
                if user:
                    formatted_requests.append({
                        'id': req.id,
                        'username': user.nickname or decode_username(user.username),
                        'request_time': format_time(req.joined_at)
                    })
            
            if formatted_requests:
                pending_chat_requests[room.id] = formatted_requests
    
    # 获取收到的好友请求
    friend_requests = FriendRequest.query.filter_by(
        receiver_id=session['user_id'],
        status='pending'
    ).all()
    
    formatted_friend_requests = []
    for req in friend_requests:
        user = User.query.get(req.sender_id)
        if user:
            formatted_friend_requests.append({
                'id': req.id,
                'sender_id': req.sender_id,
                'username': user.nickname or decode_username(user.username),
                'request_time': format_time(req.created_at)
            })
    
    # 获取当前用户收到的聊天室邀请请求
    user_invitations = ChatRoomMember.query.filter_by(
        user_id=session['user_id'],
        status='pending'
    ).all()
    
    formatted_invitations = []
    for invite in user_invitations:
        room = ChatRoom.query.get(invite.chat_room_id)
        if room:
            formatted_invitations.append({
                'id': invite.id,
                'room_id': room.id,
                'room_name': room.name,
                'request_time': format_time(invite.joined_at),
                'role': invite.role
            })
    
    return render_template('manage_requests.html', 
                           pending_chat_requests=pending_chat_requests, 
                           room_names=room_names, 
                           friend_requests=formatted_friend_requests,
                           user_invitations=formatted_invitations,
                           chat_rooms=chat_rooms)

# 批准请求
@app.route('/approve_request', methods=['POST'])
def approve_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id')
    if not request_id:
        return redirect(url_for('manage_requests'))
    
    # 查找请求
    member_request = ChatRoomMember.query.get(request_id)
    if not member_request:
        return redirect(url_for('manage_requests'))
    
    # 检查请求是否是当前用户自己的请求
    if member_request.user_id == session['user_id']:
        return redirect(url_for('manage_requests'))
    
    # 检查当前用户是否有权限管理该聊天室
    current_member = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == member_request.chat_room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if not current_member:
        return redirect(url_for('manage_requests'))
    
    # 批准请求
    member_request.status = 'approved'
    db.session.commit()
    
    return redirect(url_for('manage_requests'))

# 拒绝请求
@app.route('/reject_request', methods=['POST'])
def reject_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id')
    if not request_id:
        return redirect(url_for('manage_requests'))
    
    # 查找请求
    member_request = ChatRoomMember.query.get(request_id)
    if not member_request:
        return redirect(url_for('manage_requests'))
    
    # 检查请求是否是当前用户自己的请求
    if member_request.user_id == session['user_id']:
        return redirect(url_for('manage_requests'))
    
    # 检查当前用户是否有权限管理该聊天室
    current_member = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == member_request.chat_room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if not current_member:
        return redirect(url_for('manage_requests'))
    
    # 拒绝请求（删除记录）
    db.session.delete(member_request)
    db.session.commit()
    
    return redirect(url_for('manage_requests'))

# 接受聊天室邀请
@app.route('/accept_invitation', methods=['POST'])
def accept_invitation():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    invite_id = request.form.get('invite_id')
    if not invite_id:
        return jsonify({'success': False, 'message': '缺少邀请ID'})
    
    # 查找邀请
    invitation = ChatRoomMember.query.get(invite_id)
    if not invitation:
        return jsonify({'success': False, 'message': '邀请不存在'})
    
    # 检查是否是当前用户的邀请
    if invitation.user_id != session['user_id']:
        return jsonify({'success': False, 'message': '没有权限处理此邀请'})
    
    # 接受邀请
    invitation.status = 'approved'
    db.session.commit()
    
    return jsonify({'success': True})

# 拒绝聊天室邀请
@app.route('/reject_invitation', methods=['POST'])
def reject_invitation():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    invite_id = request.form.get('invite_id')
    if not invite_id:
        return jsonify({'success': False, 'message': '缺少邀请ID'})
    
    # 查找邀请
    invitation = ChatRoomMember.query.get(invite_id)
    if not invitation:
        return jsonify({'success': False, 'message': '邀请不存在'})
    
    # 检查是否是当前用户的邀请
    if invitation.user_id != session['user_id']:
        return jsonify({'success': False, 'message': '没有权限处理此邀请'})
    
    # 拒绝邀请（删除记录）
    db.session.delete(invitation)
    db.session.commit()
    
    return jsonify({'success': True})

# 查找聊天室
@app.route('/search_chat_room', methods=['GET', 'POST'])
def search_chat_room():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    rooms = []
    if request.method == 'POST':
        keyword = request.form['keyword']
        
        # 搜索聊天室
        rooms = ChatRoom.query.filter(
            (ChatRoom.id == keyword) |
            (ChatRoom.name.contains(keyword)) |
            (ChatRoom.tags.contains(keyword))
        ).all()
    
    return render_template('search_chat_room.html', rooms=rooms, chat_rooms=chat_rooms)

# 加入聊天室
@app.route('/join_chat_room/<room_id>', methods=['POST'])
def join_chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 检查是否已经是成员
    existing_member = ChatRoomMember.query.filter_by(
        user_id=session['user_id'],
        chat_room_id=room_id
    ).first()
    
    if existing_member:
        return redirect(url_for('chat'))
    
    # 检查是否是聊天室的管理员或所有者
    managed_room = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if managed_room:
        # 已经是管理员或所有者，直接重定向到聊天页面
        return redirect(url_for('chat'))
    
    # 创建成员请求
    member = ChatRoomMember(
        user_id=session['user_id'],
        chat_room_id=room_id,
        role='member',
        status='pending'
    )
    
    db.session.add(member)
    db.session.commit()
    
    return redirect(url_for('chat'))

# 聊天室内页
@app.route('/chat_room/<room_id>')
def chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 检查是否为成员
    member = ChatRoomMember.query.filter_by(
        user_id=session['user_id'],
        chat_room_id=room_id,
        status='approved'
    ).first()
    
    if not member:
        return redirect(url_for('chat'))
    
    room = ChatRoom.query.get(room_id)
    messages = Message.query.filter_by(chat_room_id=room_id).order_by(Message.sent_at).all()
    
    # 获取所有聊天室成员
    members = ChatRoomMember.query.filter_by(
        chat_room_id=room_id,
        status='approved'
    ).all()
    
    # 创建用户ID到用户名的映射
    user_map = {}
    for member in members:
        user = User.query.get(member.user_id)
        user_map[user.id] = user.nickname or decode_username(user.username)
    
    # 格式化消息
    for message in messages:
        message.formatted_time = format_time(message.sent_at)
        message.sender_name = user_map.get(message.sender_id, message.sender_id)
    
    # 获取用户的聊天室列表，用于侧边栏显示
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    return render_template('chat_room.html', room=room, messages=messages, member=member, chat_rooms=chat_rooms, current_room=room)

# 邀请用户加入聊天室
@app.route('/invite_user/<room_id>', methods=['POST'])
def invite_user(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 检查当前用户是否有权限
    current_member = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if not current_member:
        return redirect(url_for('chat_room', room_id=room_id))
    
    # 获取邀请信息
    user_id_or_username = request.form['user_id']
    role = request.form['role']
    
    # 查找被邀请的用户
    user = None
    
    # 先按ID查找
    user = User.query.filter_by(id=user_id_or_username).first()
    
    # 按用户名查找
    if not user:
        encoded_username = encode_username(user_id_or_username)
        user = User.query.filter(User.username.contains(encoded_username)).first()
    
    if not user:
        return redirect(url_for('chat_room', room_id=room_id))
    
    # 检查是否已经是成员
    existing_member = ChatRoomMember.query.filter_by(
        user_id=user.id,
        chat_room_id=room_id
    ).first()
    
    if existing_member:
        return redirect(url_for('chat_room', room_id=room_id))
    
    # 创建邀请记录
    member_request = ChatRoomMember(
        user_id=user.id,
        chat_room_id=room_id,
        role=role,
        status='pending'
    )
    
    db.session.add(member_request)
    db.session.commit()
    
    return redirect(url_for('chat_room', room_id=room_id))

# 违禁词管理页面
@app.route('/manage_forbidden_words/<room_id>')
def manage_forbidden_words(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 检查当前用户是否有权限
    current_member = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if not current_member:
        return redirect(url_for('chat_room', room_id=room_id))
    
    # 获取聊天室信息
    room = ChatRoom.query.get(room_id)
    if not room:
        return redirect(url_for('chat'))
    
    # 获取当前聊天室的违禁词列表
    forbidden_words = ForbiddenWord.query.filter_by(
        chat_room_id=room_id
    ).all()
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    return render_template('manage_forbidden_words.html', room=room, forbidden_words=forbidden_words, chat_rooms=chat_rooms)

# 添加违禁词
@app.route('/add_forbidden_word/<room_id>', methods=['POST'])
def add_forbidden_word(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 检查当前用户是否有权限
    current_member = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if not current_member:
        return redirect(url_for('chat_room', room_id=room_id))
    
    # 获取表单数据
    word = request.form.get('word', '').strip()
    action = request.form.get('action', 'block')
    
    if not word:
        return redirect(url_for('manage_forbidden_words', room_id=room_id))
    
    # 检查违禁词是否已存在
    existing_word = ForbiddenWord.query.filter(
        ForbiddenWord.chat_room_id == room_id,
        ForbiddenWord.word == word
    ).first()
    
    if not existing_word:
        # 创建新的违禁词
        new_word = ForbiddenWord(
            chat_room_id=room_id,
            word=word,
            action=action
        )
        db.session.add(new_word)
        db.session.commit()
    
    return redirect(url_for('manage_forbidden_words', room_id=room_id))

# 删除违禁词
@app.route('/delete_forbidden_word/<word_id>', methods=['POST'])
def delete_forbidden_word(word_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 查找违禁词
    forbidden_word = ForbiddenWord.query.get(word_id)
    if not forbidden_word:
        return redirect(url_for('chat'))
    
    # 检查当前用户是否有权限
    current_member = ChatRoomMember.query.filter(
        ChatRoomMember.user_id == session['user_id'],
        ChatRoomMember.chat_room_id == forbidden_word.chat_room_id,
        ChatRoomMember.role.in_(['owner', 'admin']),
        ChatRoomMember.status == 'approved'
    ).first()
    
    if not current_member:
        return redirect(url_for('chat_room', room_id=forbidden_word.chat_room_id))
    
    # 删除违禁词
    db.session.delete(forbidden_word)
    db.session.commit()
    
    return redirect(url_for('manage_forbidden_words', room_id=forbidden_word.chat_room_id))

# 发送消息
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    chat_room_id = request.form.get('chat_room_id')
    friend_id = request.form.get('friend_id')
    content = request.form['content']
    reply_to = request.form.get('reply_to')
    
    # 检查消息大小
    if len(content.encode()) > 5 * 1024:
        return jsonify({'success': False, 'message': '消息大小超过5KB'})
    
    # 检查消息频率和重复度
    is_allowed, error_msg = check_message_spam(session['user_id'], content)
    if not is_allowed:
        return jsonify({'success': False, 'message': error_msg})
    
    # 处理链接
    content = process_links(content)
    
    # 处理违禁词（仅聊天室消息需要检查违禁词）
    if chat_room_id:
        processed_content, is_allowed = process_forbidden_words(content, chat_room_id)
        if not is_allowed:
            return jsonify({'success': False, 'message': '消息包含违禁词，禁止发送'})
    else:
        processed_content = content
    
    # 创建消息
    new_message = Message(
        sender_id=session['user_id'],
        chat_room_id=chat_room_id,
        friend_id=friend_id,
        content=processed_content,
        reply_to=reply_to
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    return jsonify({'success': True})

# 撤回消息
@app.route('/recall_message/<message_id>', methods=['POST'])
def recall_message(message_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'success': False, 'message': '消息不存在'})
    
    # 检查权限
    user_id = session['user_id']
    
    # 普通用户只能撤回自己的消息
    if message.sender_id != user_id:
        # 检查是否为管理员或房主
        if message.chat_room_id:
            member = ChatRoomMember.query.filter_by(
                user_id=user_id,
                chat_room_id=message.chat_room_id
            ).first()
            
            if not member or member.role not in ['admin', 'owner']:
                return jsonify({'success': False, 'message': '没有权限撤回此消息'})
        else:
            # 私聊只能撤回自己的消息
            return jsonify({'success': False, 'message': '没有权限撤回此消息'})
    
    # 撤回消息
    message.is_撤回 = True
    db.session.commit()
    
    # 通知所有客户端消息已撤回
    if message.chat_room_id:
        # 聊天室消息，广播给所有房间成员
        socketio.emit('message_recalled', {
            'message_id': message.id,
            'chat_room_id': message.chat_room_id
        }, room=message.chat_room_id)
    
    return jsonify({'success': True})

# WebSocket 事件处理

# 存储用户连接信息，key为user_id，value为sid
user_sockets = {}
# 存储房间成员，key为room_id，value为set of user_id
room_members = {}

# 连接事件
@socketio.on('connect')
def handle_connect():
    print(f"客户端连接: {request.sid}")
    emit('connect_success', {'message': '连接成功'})

# 断开连接事件
@socketio.on('disconnect')
def handle_disconnect():
    print(f"客户端断开: {request.sid}")
    # 移除用户连接信息
    for user_id, sid in list(user_sockets.items()):
        if sid == request.sid:
            del user_sockets[user_id]
            # 从所有房间移除用户
            for room_id, members in list(room_members.items()):
                if user_id in members:
                    members.remove(user_id)
            break

# 心跳事件 - 客户端发送ping
@socketio.on('ping')
def handle_ping():
    emit('pong')

# 加入聊天室
@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id')
    
    if not room_id or not user_id:
        emit('error', {'message': '缺少必要参数'})
        return
    
    # 验证用户是否有权限加入聊天室
    member = ChatRoomMember.query.filter_by(
        user_id=user_id,
        chat_room_id=room_id,
        status='approved'
    ).first()
    
    if not member:
        emit('error', {'message': '没有权限加入该聊天室'})
        return
    
    # 加入房间
    join_room(room_id)
    
    # 存储连接信息
    user_sockets[user_id] = request.sid
    
    # 更新房间成员列表
    if room_id not in room_members:
        room_members[room_id] = set()
    room_members[room_id].add(user_id)
    
    print(f"用户 {user_id} 加入聊天室 {room_id}")
    emit('join_success', {'room_id': room_id, 'user_id': user_id})

# 发送消息
@socketio.on('send_message')
def handle_send_message(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id')
    content = data.get('content', '').strip()
    
    if not room_id or not user_id or not content:
        emit('error', {'message': '缺少必要参数'})
        return
    
    # 验证用户是否在聊天室中
    member = ChatRoomMember.query.filter_by(
        user_id=user_id,
        chat_room_id=room_id,
        status='approved'
    ).first()
    
    if not member:
        emit('error', {'message': '没有权限发送消息'})
        return
    
    # 检查消息大小
    if len(content) > 5 * 1024:
        emit('error', {'message': '消息长度超过限制'})
        return
    
    # 检查消息频率和重复度
    is_allowed, error_msg = check_message_spam(user_id, content)
    if not is_allowed:
        # 发送spam_warning事件
        emit('spam_warning', {'message': error_msg})
        return
    
    # 处理链接
    content = process_links(content)
    
    # 处理违禁词
    processed_content, is_allowed = process_forbidden_words(content, room_id)
    if not is_allowed:
        emit('error', {'message': '消息包含违禁词，禁止发送'})
        return
    
    # 创建消息
    new_message = Message(
        id=str(uuid.uuid4()),
        sender_id=user_id,
        chat_room_id=room_id,
        content=processed_content,
        sent_at=time.time(),
        is_撤回=False
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    # 获取发送者信息
    sender = User.query.get(user_id)
    sender_name = sender.nickname or decode_username(sender.username)
    
    # 格式化消息，不包含is_own字段，由客户端根据自己的user_id判断
    formatted_message = {
        'id': new_message.id,
        'sender_id': new_message.sender_id,
        'chat_room_id': new_message.chat_room_id,
        'content': new_message.content,
        'sent_at': new_message.sent_at,
        'is_撤回': new_message.is_撤回,
        'sender_name': sender_name,
        'formatted_time': format_time(new_message.sent_at)
    }
    
    # 发送消息给房间内所有成员
    emit('new_message', formatted_message, room=room_id)
    
    print(f"用户 {user_id} 在聊天室 {room_id} 发送消息: {content}")

# 撤回消息
@socketio.on('recall_message')
def handle_recall_message(data):
    message_id = data.get('message_id')
    user_id = data.get('user_id')
    
    if not message_id or not user_id:
        emit('error', {'message': '缺少必要参数'})
        return
    
    # 查找消息
    message = Message.query.get(message_id)
    if not message:
        emit('error', {'message': '消息不存在'})
        return
    
    # 验证权限（只有发送者可以撤回消息）
    if message.sender_id != user_id:
        emit('error', {'message': '没有权限撤回该消息'})
        return
    
    # 更新消息状态
    message.is_撤回 = True
    db.session.commit()
    
    # 通知房间内所有成员
    emit('message_recalled', {
        'message_id': message_id,
        'chat_room_id': message.chat_room_id
    }, room=message.chat_room_id)
    
    print(f"用户 {user_id} 撤回消息: {message_id}")

# 离开聊天室
@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id')
    
    if not room_id or not user_id:
        emit('error', {'message': '缺少必要参数'})
        return
    
    # 离开房间
    leave_room(room_id)
    
    # 更新房间成员列表
    if room_id in room_members:
        if user_id in room_members[room_id]:
            room_members[room_id].remove(user_id)
            if not room_members[room_id]:
                del room_members[room_id]
    
    print(f"用户 {user_id} 离开聊天室 {room_id}")
    emit('leave_success', {'room_id': room_id, 'user_id': user_id})

# 长轮询获取新消息（保留旧API，确保兼容性）
@app.route('/get_new_messages/<room_id>')
def get_new_messages(room_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    # 检查是否为聊天室成员
    member = ChatRoomMember.query.filter_by(
        user_id=session['user_id'],
        chat_room_id=room_id,
        status='approved'
    ).first()
    
    if not member:
        return jsonify({'success': False, 'message': '不是聊天室成员'})
    
    # 获取参数
    last_message_id = request.args.get('last_message_id', '')
    
    # 获取聊天室所有成员
    members = ChatRoomMember.query.filter_by(
        chat_room_id=room_id,
        status='approved'
    ).all()
    
    # 创建用户ID到用户名的映射
    user_map = {}
    for member in members:
        user = User.query.get(member.user_id)
        user_map[user.id] = user.nickname or decode_username(user.username)
    
    # 长轮询等待新消息
    start_time = time.time()
    new_messages = []
    
    # 获取最后一条消息的发送时间
    last_sent_at = 0
    if last_message_id:
        # 查找最后一条消息
        last_message = Message.query.get(last_message_id)
        if last_message:
            last_sent_at = last_message.sent_at
    
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
            # 格式化消息
            new_messages = []
            for message in messages:
                new_messages.append({
                    'id': message.id,
                    'sender_id': message.sender_id,
                    'sender_name': user_map.get(message.sender_id, message.sender_id),
                    'content': message.content,
                    'formatted_time': format_time(message.sent_at),
                    'is_撤回': message.is_撤回,
                    'is_own': message.sender_id == session['user_id']
                })
            break
        
        # 没有新消息，等待一段时间
        time.sleep(1)
    
    # 获取最后一条消息的ID
    last_id = ""
    if new_messages:
        last_id = new_messages[-1]['id']
    elif last_message_id:
        last_id = last_message_id
    
    return jsonify({
        'success': True,
        'new_messages': new_messages,
        'last_message_id': last_id
    })

# 获取聊天室成员
@app.route('/get_chat_room_members/<room_id>')
def get_chat_room_members(room_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    members = ChatRoomMember.query.filter_by(
        chat_room_id=room_id,
        status='approved'
    ).all()
    
    member_list = []
    for member in members:
        user = User.query.get(member.user_id)
        member_list.append({
            'id': user.id,
            'username': user.nickname or decode_username(user.username),
            'role': member.role
        })
    
    return jsonify({'success': True, 'members': member_list})

# 搜索用户
@app.route('/search_user', methods=['GET', 'POST'])
def search_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    users_with_decoded_name = []
    if request.method == 'POST':
        keyword = request.form['keyword']
        
        # 搜索用户
        # 按用户名搜索
        encoded_keyword = encode_username(keyword)
        users_by_username = User.query.filter(User.username.contains(encoded_keyword)).all()
        
        # 按ID搜索
        users_by_id = User.query.filter_by(id=keyword).all()
        
        # 合并结果
        users = list(set(users_by_username + users_by_id))
        
        # 解码用户名
        for user in users:
            user.decoded_username = decode_username(user.username)
            users_with_decoded_name.append(user)
    
    return render_template('search_user.html', users=users_with_decoded_name, chat_rooms=chat_rooms)

# 添加好友
@app.route('/add_friend/<user_id>', methods=['POST'])
def add_friend(user_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    # 检查是否已经是好友
    existing_friendship1 = Friendship.query.filter_by(
        user1_id=session['user_id'],
        user2_id=user_id
    ).first()
    existing_friendship2 = Friendship.query.filter_by(
        user1_id=user_id,
        user2_id=session['user_id']
    ).first()
    
    if existing_friendship1 or existing_friendship2:
        return jsonify({'success': False, 'message': '已经是好友'})
    
    # 检查是否已经发送过请求
    existing_request = FriendRequest.query.filter_by(
        sender_id=session['user_id'],
        receiver_id=user_id
    ).first()
    
    if existing_request:
        return jsonify({'success': False, 'message': '已经发送过请求'})
    
    # 创建好友请求
    new_request = FriendRequest(
        sender_id=session['user_id'],
        receiver_id=user_id
    )
    
    db.session.add(new_request)
    db.session.commit()
    
    return jsonify({'success': True})

# 处理好友请求
@app.route('/handle_friend_request/<request_id>/<action>', methods=['POST'])
def handle_friend_request(request_id, action):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    friend_request = FriendRequest.query.get(request_id)
    if not friend_request:
        return jsonify({'success': False, 'message': '请求不存在'})
    
    if friend_request.receiver_id != session['user_id']:
        return jsonify({'success': False, 'message': '没有权限处理此请求'})
    
    if action == 'accept':
        # 创建好友关系
        friendship1 = Friendship(
            user1_id=friend_request.sender_id,
            user2_id=friend_request.receiver_id
        )
        friendship2 = Friendship(
            user1_id=friend_request.receiver_id,
            user2_id=friend_request.sender_id
        )
        
        db.session.add(friendship1)
        db.session.add(friendship2)
        friend_request.status = 'accepted'
    else:
        friend_request.status = 'rejected'
    
    db.session.commit()
    
    return jsonify({'success': True})

# 编辑个人信息
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    user = User.query.get(session['user_id'])
    # 获取用户的快捷短语
    quick_phrases = QuickPhrase.query.filter_by(user_id=session['user_id']).order_by(QuickPhrase.created_at).all()
    
    if request.method == 'POST':
        user.nickname = request.form['nickname']
        user.bio = request.form.get('bio', '')
        
        db.session.commit()
        return redirect(url_for('edit_profile'))
    
    return render_template('edit_profile.html', user=user, chat_rooms=chat_rooms, quick_phrases=quick_phrases)

# 添加快捷短语
@app.route('/add_quick_phrase', methods=['POST'])
def add_quick_phrase():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    phrase = request.form.get('phrase', '').strip()
    if not phrase:
        return redirect(url_for('edit_profile'))
    
    # 添加快捷短语
    new_phrase = QuickPhrase(
        user_id=session['user_id'],
        content=phrase
    )
    db.session.add(new_phrase)
    db.session.commit()
    
    return redirect(url_for('edit_profile'))

# 删除快捷短语
@app.route('/delete_quick_phrase/<phrase_id>', methods=['POST'])
def delete_quick_phrase(phrase_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 查找快捷短语
    quick_phrase = QuickPhrase.query.get(phrase_id)
    if not quick_phrase:
        return redirect(url_for('edit_profile'))
    
    # 检查是否为当前用户的快捷短语
    if quick_phrase.user_id != session['user_id']:
        return redirect(url_for('edit_profile'))
    
    # 删除快捷短语
    db.session.delete(quick_phrase)
    db.session.commit()
    
    return redirect(url_for('edit_profile'))

# 获取用户快捷短语
@app.route('/get_quick_phrases')
def get_quick_phrases():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    # 获取用户的快捷短语
    quick_phrases = QuickPhrase.query.filter_by(user_id=session['user_id']).order_by(QuickPhrase.created_at).all()
    
    # 格式化返回数据
    phrases_list = []
    for phrase in quick_phrases:
        phrases_list.append({
            'id': phrase.id,
            'content': phrase.content
        })
    
    return jsonify({'success': True, 'phrases': phrases_list})

# 修改密码
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 获取用户的聊天室列表
    chat_rooms = get_user_chat_rooms(session['user_id'])
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        
        # 验证原密码
        if user.password != hash_password(old_password):
            return render_template('change_password.html', error='原密码错误')
        
        # 验证新密码
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return render_template('change_password.html', error=error_msg)
        
        user.password = hash_password(new_password)
        db.session.commit()
        
        # 退出登录
        session.pop('user_id', None)
        session.pop('username', None)
        
        return redirect(url_for('login'))
    
    return render_template('change_password.html', chat_rooms=chat_rooms)
