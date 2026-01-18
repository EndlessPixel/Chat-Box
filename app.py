from extensions import app, db

# 导入模型和路由
from models import *
from routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)