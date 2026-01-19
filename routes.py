from extensions import app, db
from models import *
from flask import render_template, request, redirect, url_for, session, jsonify
import base64
import hashlib
import uuid
import time

# 辅助函数
def hash_password(password):
    return hashlib.sha512(password.encode()).hexdigest()

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
    
    # 获取所有待审核请求
    pending_chat_requests = {}
    room_names = {}
    
    for managed in managed_rooms:
        room = ChatRoom.query.get(managed.chat_room_id)
        if not room:
            continue
        
        room_names[room.id] = room.name
        
        # 获取该聊天室的待审核请求
        requests = ChatRoomMember.query.filter_by(
            chat_room_id=room.id,
            status='pending'
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
    
    return render_template('chat_room.html', room=room, messages=messages, member=member, chat_rooms=chat_rooms)

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
    
    # 创建消息
    new_message = Message(
        sender_id=session['user_id'],
        chat_room_id=chat_room_id,
        friend_id=friend_id,
        content=content,
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
    
    return jsonify({'success': True})

# 长轮询获取新消息
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
    
    if request.method == 'POST':
        user.nickname = request.form['nickname']
        user.bio = request.form.get('bio', '')
        
        db.session.commit()
        return redirect(url_for('chat'))
    
    return render_template('edit_profile.html', user=user, chat_rooms=chat_rooms)

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
