from extensions import app, db
from models import *

with app.app_context():
    db.create_all()
    print("数据库初始化完成，所有表已创建")
    print("exit 0")