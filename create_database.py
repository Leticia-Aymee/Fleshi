from appfleshi import database, app
from appfleshi.models import Photo, User, Like

with app.app_context():
    database.create_all()