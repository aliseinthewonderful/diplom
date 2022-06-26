from flask import request, jsonify, render_template, redirect, session, url_for
from functools import wraps
from app import app, bcrypt, db, login_manager
from flask_wtf import FlaskForm
from flask_login import login_required, current_user, login_user, logout_user
from wtforms import StringField, BooleanField, IntegerField, TextAreaField
from wtforms.validators import DataRequired
from flask_admin import Admin
from flask_admin import AdminIndexView
from flask_admin.contrib.sqla import ModelView
from app import validators
from app.models.catalog import Product, Service
from app.models.orders import CompletedOrder, IncomingOrder, ProcessingOrder
from app.models.admin import Post, slugify
from app.models.users import User

import json
import uuid
from yookassa import Configuration, Payment

_ROLES = {
    "CLIENT": 0,  # КЛИЕНТ
    "WORKER": 1,  # РАБОТНИК
    "EMPLOYEE": 2,  # СОТРУДНИК/АДМИН
}

Configuration.configure(
    '906681', 'test_0tzxgZ9aoaNhzbIMnu86TwZwry-hA7SMpmrURhbfE4M')

# FORMS


class LoginForm(FlaskForm):
    login = StringField('login', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired()])
    remember_me = BooleanField('remember')
    role = IntegerField('role', default=0)


class RegisterForm(FlaskForm):
    login = StringField('login', validators=[DataRequired()])
    name = StringField('name', validators=[DataRequired()])
    surname = StringField('surname', validators=[DataRequired()])
    middle_name = StringField('middle_name', validators=[DataRequired()])
    phone = StringField('phone', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired()])

class EditForm(FlaskForm):
    products = StringField('products')
    services = StringField('services')
    comment = StringField('comment')
    cost = IntegerField('cost',  validators=[DataRequired()])




@login_manager.user_loader
def load_user(user_id):
    """Функция callback, которая используется библиотекой для получения ID пользователя из сессии (Когда он авторизовался и просто что-то открывает)
    Args:
        user_id (int): ID ползователя
    Returns:
        User: Объект пользователя
    """
    return User.query.get(int(user_id))

# UTILITIES


def only_worker(func):
    """Декоратор (функция-обертка), которая проверяет, является ли текущий пользователь Работником или Админом.
    Если да, то продолжает выполнение кода.
    Иначе перенаправляет на главную страницу.
    Используем для страниц, которые может открывать только работник
    """
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.role != 1 and not current_user.is_admin:
            return redirect('/')
        return func(*args, **kwargs)
    return decorated_view


def only_employee(func):
    """Декоратор (функция-обертка), которая проверяет, является ли текущий пользователь Сотрудником или Админом.
    Если да, то продолжает выполнение кода.
    Иначе перенаправляет на главную страницу.
    Используем для страниц, которые может открывать только сотрудник
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.role != 2 and not current_user.is_admin:
            return redirect('/')
        return func(*args, **kwargs)
    return decorated_view


def create_user(login, name, phone, _password):
    """Создает запись пользователя в БД.
    Используем при регистрации.

    Args:
        login (string): Логин
        name (string): ФИО пользователя
        phone (int): Номер телефона
        _password (string): Пароль в сыром виде (незашифрован)

    Returns:
        User: Объект пользователя
    """
    # Хэшируем пароль
    password = bcrypt.generate_password_hash(_password).decode('utf-8')
    # Создаем запись в БД User
    user = User(name, login, password, phone)
    db.session.add(user)
    db.session.commit()
    return user


@app.context_processor
def get_user_processor():
    """Позволяет  получать объект пользователя прямиком из HTML (через шаблонизатор)"""
    def get_user(user_id):
        return User.query.get(int(user_id))
    return dict(get_user=get_user)


class AdminView(ModelView):
    form_args = {
        'title': {
            'widget': TextAreaField.widget
        },
        'body': {
            'widget': TextAreaField.widget,
        }
    }

    form_widget_args = {
        'body': {
            'rows': 10,
        }
    }

    def is_accessible(self):
        return current_user and current_user.is_authenticated and current_user.role == 2 and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect('/')
        return redirect(url_for('security.login', next=request.url))


class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user and current_user.is_authenticated and current_user.role == 2 and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect('/')
        return redirect(url_for('security.login', next=request.url))


# admin
admin = Admin(app, 'FlaskApp', url='/', index_view=HomeAdminView(name='Home'))
admin.add_view(AdminView(Post, db.session))
admin.add_view(AdminView(Service, db.session))
admin.add_view(AdminView(Product, db.session))

# Posts with pages

def truncate_long_string(string, max_length):
    if len(string) > max_length:
        string = string[:max_length - 3] + '...'

    return string


def format_date(date):
    return date.strftime("%d.%m.%Y")


def format_posts(posts):
    max_length = 150
    formatted_posts = []
    for post in posts:
        new_post = post

        if hasattr(post, 'body'):
            new_post.body = "{0:<10s}".format(
                truncate_long_string(new_post.body, max_length))

        new_post.date_formatted = format_date(new_post.date)

        formatted_posts.append(new_post)

    return formatted_posts


def get_last_posts():
    posts = Post.query.order_by(Post.id.desc()).limit(3).all()
    return format_posts(posts)


def get_posts_paginated(page):
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1

    posts_paginated = Post.query.order_by(
        Post.id.desc()).paginate(page=page, per_page=3)
    posts_paginated.items = format_posts(posts_paginated.items)

    return posts_paginated


@app.route("/")
def index():
    page = request.args.get('page')

    posts_paginated = get_posts_paginated(page)
    last_posts = get_last_posts()

    return render_template("index.html", posts_paginated=posts_paginated, last_posts=last_posts)

# @app.route("/posts")
# def posts_page1():
#     posts = Post.query.all()
#     return render_template("posts.html", posts=posts)


@app.route("/posts/<slug>")
def post(slug):
    post = Post.query.filter(Post.slug == slug).first()
    return render_template("detail_post.html", post=post)


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/social-activities")
def socialActivitiesPage():
    return render_template("social-activities.html")


@app.route("/documents")
def documents():
    return render_template("documents.html")


@app.route("/join")
def join():
    return render_template("join.html")


@app.route("/rasskrinf")
def rasskrinf():
    return render_template("rasskrinf.html")


@app.route("/symbolism")
def symbolism():
    return render_template("symbolism.html")


@app.route("/ustav")
def ustav():
    return render_template("ustav.html")


@app.route("/targets")
def targets():
    return render_template("targets.html")


@app.route("/contacts")
def contacts():
    return render_template("contacts.html")


@app.route("/ispit-mont-p")
def ispitMontP():
    return render_template("ispit_mont_p.html")


@app.route("/ognezobr")
def ognezobr():
    return render_template("ognezobr.html")


@app.route("/plan")
def plan():
    return render_template("plan.html")


@app.route("/project")
def project():
    return render_template("project.html")


@app.route("/tehobsl")
def tehobsl():
    return render_template("tehobsl.html")


@app.route("/obuchp")
def obuchp():
    return render_template("obuchp.html")


@app.route("/obuchmotorist")
def obuchmotorist():
    return render_template("obuchmotorist.html")


@app.route("/obuchdpk")
def obuchdpk():
    return render_template("obuchdpk.html")


@app.route("/dopobraz")
def dopobraz():
    return render_template("dopobraz.html")


@app.route("/vakant")
def vakant():
    return render_template("vakant.html")


@app.route("/obuchGOCHS")
def obuchGOCHS():
    return render_template("obuchGOCHS.html")


@app.route("/lk")
@login_required
def lk():
    user_id = int(current_user.id)

    # Если пользователь клиент
    if current_user.role == 0:
        # Получаем все заказы, созданные им, фильтруя по client_id и deprecated (если заказы уже не действительны)
        incoming_orders = IncomingOrder.query.filter_by(
            client_id=user_id, deprecated=False).all()

        processing_orders = ProcessingOrder.query.filter_by(
            client_id=user_id, deprecated=False).all()

        current_orders = incoming_orders + processing_orders
        completed_orders = CompletedOrder.query.filter_by(
            client_id=user_id).all()

        # current_orders = Новые заказы, либо заказы в процессе исполнения
        # completed_orders = Выполненные заказы
        return render_template("lk.html", name=current_user.name, current_orders=current_orders, completed_orders=completed_orders)

    elif current_user.role > 0:
        # Откроываем особый ЛК, если пользователь относится к персоналу
        return render_template("staff.html", user=current_user, name=current_user.name, is_admin=current_user.is_admin)


@app.route("/orders/new")
@login_required
@only_employee
def new_orders():
    orders = IncomingOrder.query.filter_by(
        deprecated=False).all()  # Получаем все новые заказы
    workers = User.query.filter_by(role=1).all()  # Получаем всех работников

    # Передаем в HTML
    return render_template("new_orders.html", user=current_user, workers=workers, orders=orders, is_admin=current_user.is_admin)


@app.route("/orders/processing")
@login_required
@only_worker
def processing_orders():
    if current_user.is_admin:
        orders = ProcessingOrder.query.filter(ProcessingOrder.deprecated.is_(False), ProcessingOrder.worker_id.isnot(None)).all()
    else:
        user_id = int(current_user.id)
        orders = ProcessingOrder.query.filter(
                ProcessingOrder.worker_id.is_(user_id), ProcessingOrder.deprecated.is_(False)).all()

    # Передаем в HTML
    return render_template("processing_orders.html", user=current_user, orders=orders, is_admin=current_user.is_admin)


@app.route("/orders/delivery")
@login_required
@only_employee
def delivery_orders():
    # Получаем все заказы, в которых только товары. Это реализовано так, что хранятся они в БД заказов в исполнении, просто у них нет worker_id (NULL)
    orders = ProcessingOrder.query.filter(
        ProcessingOrder.worker_id.is_(None), ProcessingOrder.deprecated.is_(False)).all()

    return render_template("delivery_orders.html", user=current_user, orders=orders, is_admin=current_user.is_admin)


@app.route("/orders/completed")
@login_required
@only_employee
def completed_orders():
    if not current_user.is_admin:
        return redirect('/')

    orders = CompletedOrder.query.all()
    return render_template("completed_orders.html", user=current_user, orders=orders, is_admin=current_user.is_admin)


@app.route("/cart")
@login_required
def cart():
    # Получаем все товары из корзины. Корзина находится в сессии (cookie)

    cart = session['cart'] if 'cart' in session else []
    # Общая стоимость товаров
    cost = 0
    for item in cart:
        # Если есть цена у товара
        if item['price'] is not None:
            # Высчитаем цену товара через (кол-во * цену за штуку)
            count = item['count'] if 'count' in item else 1
            price = item['price'] * count
            # Прибавляем к общей стоимости
            cost += price

    return render_template("cart.html", cart=cart, cost=cost)


@app.route("/products")
def products_page():
    products = Product.query.all()

    return render_template("products.html", products=products, user=current_user)


@app.route("/services")
def services_page():
    services = Service.query.all()

    return render_template("services.html", services=services, user=current_user)


# logout
@app.route("/logout")
@login_required
def logout():
    """Выйти из аккаунта"""
    logout_user()
    return redirect("/")


# AUTH
@app.route("/register", methods=['GET', 'POST'])
def reg_page():
    # Если пользователь уже авторизован, то редиректим на главную
    if current_user.is_authenticated:
        return redirect("/")

    # Тут мы используем библиотеку-валидатор форм flask_wtf
    form = RegisterForm()

    # При отправки формы:
    if form.validate_on_submit():
        # Получаем данные из полей
        login = form.login.data
        name = form.name.data
        surname = form.surname.data
        middle_name = form.middle_name.data
        phone = form.phone.data
        password = form.password.data

        # Ищем пользователя по логину
        is_registered = len(User.query.filter_by(
            login=login, role=0).all()) >= 1

        # Если он не зарегистрирован - создаем и редиректим на авторизацию
        if not is_registered:
            create_user(
                login, f"{surname} {name} {middle_name}", phone, password)
            return redirect("/auth")

    return render_template("reg.html", form=form)


@app.route("/auth", methods=['GET', 'POST'])
def auth_page():
    # Получаем роль, в который мы авторизуемся из GET параметров. ?type=worker.
    user_type = request.args.get('type', default='client', type=str)
    role = 0

    roles = {
        "client": 0,
        "employee": 2,
        "worker": 1
    }

    # Записываем в role ID роли.
    if user_type in roles:
        role = roles[user_type]

    # Если пользователь уже авторизован и его роль == типу
    if current_user and current_user.is_authenticated and current_user.role == role:
        return redirect("/")
    elif current_user:
        # Иначе просто выходим из аккаунта
        logout_user()

    # Валидатор логин формы
    form = LoginForm()
    if form.validate_on_submit():
        login = form.login.data
        password = form.password.data
        remember_me = form.remember_me.data

        # Получаем пользователя
        user = User.query.filter_by(login=login, role=role).first()

        # Если него нет, то просто перезагружаем страницу
        if not user:
            return redirect(request.url)

        # Если пароли не совпадают, то просто перезагружаем страницу
        if role > 0 and user.password != password:
            return redirect(request.url)

        # Если пароли не совпадают, то просто перезагружаем страницу
        if role == 0 and not bcrypt.check_password_hash(user.password, password):
            return redirect(request.url)

        # Авторизуемся
        login_user(user, remember=remember_me)
        return redirect('/')

    return render_template("auth.html", form=form)


# API
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    validate = validators.user.validate(data)
    if not validate['success']:
        return validate['error'], 400

    name = data['name'] if 'name' in data else False
    if not name:
        return jsonify({'status': False}), 404

    login = data['login']
    phone = data['phone'] if 'phone' in data else ""

    is_registered = len(User.query.filter_by(login=login).all()) >= 1

    if is_registered:
        return jsonify({'status': False}), 404

    create_user(login, name, phone, data['password'])
    return jsonify({'status': True})



@app.route('/api/cart/add', methods=['POST'])
@login_required
def add_cart():
    """Добавить предмет в корзину"""

    # Если корзины нет, то создает объект корзины. (пустой)
    if 'cart' not in session:
        session['cart'] = []

    data = request.get_json() or {}
    fields = ['id', 'type']
    for field in fields:
        if field not in data:
            return jsonify({'status': False}), 400

    item_id = int(data['id'])
    item_type = 'products' if data['type'] == 'products' else 'services'
    count = int(data['count']) if 'count' in data else 1

    # Определеям тип предмета (товар или услуга)
    Item = Product if item_type == "products" else Service
    # Получаем объект товара/услуги по ID
    db_item = Item.query.filter_by(id=item_id).first()

    if item_type == 'services':
        # Если предмет уже в корзину, то не добавляем
        for item in session['cart']:
            if item['id'] == item_id and item['type'] == 'services':
                return jsonify({'status': False})

        session['cart'].append({
            "id": item_id,
            "type": item_type,
            "name": db_item.name,
            "price": db_item.price,
            "count": 1
        })
        session.modified = True
        return jsonify({'status': True})

    # Добавляем количество товара при нажатии "добавить в корзину", если товар там уже лежит
    for idx, item in enumerate(session['cart']):
        if item['id'] == item_id and item['type'] == 'products':
            session['cart'][idx]['count'] += count
            session.modified = True
            return jsonify({'status': True})

    session['cart'].append({
        "id": item_id,
        "type": item_type,
        "name": db_item.name,
        "price": db_item.price,
        "count": count
    })
    session.modified = True
    return jsonify({'status': True})


@app.route('/api/cart/clear', methods=['POST'])
@login_required
def clear_cart():
    """Очистить корзину"""
    session['cart'] = []
    session.modified = True
    return jsonify({'status': True})


@app.route('/api/orders/create', methods=['POST'])
@login_required
def create_order():
    """Оформить новый заказ"""
    data = request.get_json() or {}
    client_id = int(current_user.id)

    use_delivery = data['delivery'] if 'delivery' in data else False
    address = data['address'] if 'address' in data else ""
    comment = data['comment'] if 'comment' in data else ""
    oplata = data['oplata'] if 'oplata' in data else ""
    cost = data['cost'] if 'cost' in data else ""
    paymentType = data['paymentType'] if 'paymentType' in data else ""

    if 'cart' not in session and len(session['cart']) == 0:
        return jsonify({'status': False}), 400

    cart = session['cart']

    # Получаем все товары из корзины
    products = list(filter(lambda x: x['type'] == "products", cart))
    # Получаем все услуги из корзины
    services = list(filter(lambda x: x['type'] == "services", cart))

    # Создаем объект нового заказа
    order = IncomingOrder(
        client_id, products, services, comment, address, use_delivery, oplata)

    # Сохраняем в БД и очищаем корзину
    db.session.add(order)
    db.session.commit()
    session['cart'] = []
    session.modified = True

    # Если способ оплаты онлайн, то создаем платеж и возвращаем ссылку
    if paymentType == "online":
        payment = Payment.create({
            "amount": {
                "value": float(cost),
                "currency": "RUB"
            },
            "confirmation": {
                "type": "redirect",
                "return_url": "http://vdpo12.ru/"
            },
            "capture": True,
            "description": f"Номер заказа: {order.id}"

        }, uuid.uuid4())

        return jsonify({'status': True, "redirect_url": payment.confirmation.confirmation_url})

    return jsonify({'status': True})


@app.route('/api/orders/cancel', methods=['POST'])
@login_required
@only_employee
def cancel_order():
    """Отмена заказа"""
    data = request.get_json() or {}

    fields = ['order_id']
    for field in fields:
        if field not in data:
            return jsonify({'status': False}), 400

    # Поиск нового заказа по ID
    incoming_order = IncomingOrder.query.filter_by(
        id=data['order_id']).first()

    # Если заказ найден, ставим ему depreated и сохраняем
    if incoming_order is not None:
        incoming_order.deprecated = True
        db.session.commit()
        return jsonify({'status': True})

    return jsonify({'status': False}), 400


@app.route('/api/orders/submit', methods=['POST'])
@login_required
@only_employee
def submit_order():
    """Подтверждение заказа (либо отправка на выдачу)"""
    data = request.get_json() or {}

    employee_id = current_user.id
    fields = ['order_id']
    for field in fields:
        if field not in data:
            return jsonify({'status': False}), 400

    # Получение нового заказа
    incoming_order = IncomingOrder.query.filter_by(
        id=data['order_id']).first()

    if not incoming_order:
        return jsonify({'status': False}), 400

    products = incoming_order.get_products()
    services = incoming_order.get_services()

    # Если товаров и услуг нет, то возвращаем ошибку
    if not len(products) and not len(services):
        return jsonify({'status': False}), 400

    # Вычитаем количество товаров
    for product in products:
        Product.query.get(
            int(product['id'])).count -= int(product['count'])

    delivery = incoming_order.delivery

    # Способ подтверждения (Заказ выполнен, либо на выдачу, либо на исполнение)
    state = data.get('state', False)
    if not state:
        return jsonify({'status': False}), 400

    # Отправляем новый заказ на выдачу
    if state == 'delivery' and not delivery and len(products) and not len(services):
        processing_order = ProcessingOrder(
            incoming_order.id,
            incoming_order.client_id,
            employee_id,
            None,
            products,
            services,
            comment=incoming_order.comment,
            address=incoming_order.address,
            delivery=delivery,
            oplata=incoming_order.oplata
        )
        db.session.add(processing_order)

    # Отправляем новый заказ на исполнение работнику
    elif state == 'worker':
        worker_id = int(data['worker_id'])
        processing_order = ProcessingOrder(
            incoming_order.id,
            incoming_order.client_id,
            employee_id,
            worker_id,
            products,
            services,
            comment=incoming_order.comment,
            address=incoming_order.address,
            delivery=delivery,
            oplata=incoming_order.oplata
        )

        db.session.add(processing_order)

    # Ставим заказ выполненным
    else:
        completed_order = CompletedOrder(
            incoming_order.id,
            incoming_order.client_id,
            employee_id,
            None,
            products,
            services,
            comment=incoming_order.comment,
            address=incoming_order.address,
            delivery=delivery,
            oplata=incoming_order.oplata

        )
        db.session.add(completed_order)

        # Если заказ выдан, то ставим заказ в обработке deprecated
        if state == 'issued':
            processing_order = ProcessingOrder.query.filter_by(
                order_id=data['order_id']).first()
            processing_order.deprecated = True

    incoming_order.deprecated = True
    db.session.commit()
    return jsonify({'status': True})


@app.route('/api/orders/progress', methods=['POST'])
@login_required
@only_worker
def update_order_progress():
    data = request.get_json() or {}
    fields = ['order_id', 'progress']
    for field in fields:
        if field not in data:
            return jsonify({'status': False}), 400

    # Получаем заказ на исполнении
    processing_order = ProcessingOrder.query.filter_by(
        order_id=data['order_id']).first()

    products = processing_order.get_products()
    services = processing_order.get_services()

    progress = int(data['progress'])
    # Есои прогресс больше или равен 100, то заказ выполнен
    if progress >= 100:
        completed_order = CompletedOrder(processing_order.order_id,
                                         processing_order.client_id,
                                         processing_order.employee_id,
                                         current_user.id,
                                         products,
                                         services,
                                         processing_order.comment,
                                         processing_order.address,
                                         processing_order.delivery,
                                         processing_order.oplata
                                         )

        completed_order.worker_id = processing_order.worker_id
        db.session.add(completed_order)
        db.session.delete(processing_order)
    else:
        # Иначе устанавливаем прогресс
        processing_order.set_progress(progress)

    db.session.commit()
    return jsonify({'status': True})

@app.route('/api/orders/delete', methods=['POST'])
@login_required
def deleteProcessingOrder():
    request_data = request.get_json() or {}

    order_id = int(request_data['order_id'])
    processing_order = ProcessingOrder.query.filter_by(order_id=order_id, deprecated=False).first()
    processing_order.deprecated = True

    order = IncomingOrder.query.filter_by(id=order_id, deprecated=True).first()
    order.deprecated = False

    db.session.commit()

    return redirect(url_for('processing_orders'))

@app.route('/api/orders/edit', methods=['POST'])
@login_required
def edit():
    request_data = request.get_json() or {}

    order_id = int(request_data['id'])
    order= IncomingOrder.query.filter_by(id=order_id).first()

    # Если в созданных заказах нет, ищем в заказах в работе
    if not order:
        order = ProcessingOrder.query.filter_by(order_id=order_id).first()

    # Если в заказах в работе нет, ищем в завершенных заказах
    if not order:
        order = CompletedOrder.query.filter_by(order_id=order_id).first()

    new_products = request_data["products"]
    new_services = request_data["services"]

    if new_products:
        for product in new_products:
            print(product)
            if product["count"] == 0:
                new_products.remove(product)

    if new_services:
        for service in new_services:
            if service["count"] == 0:
                new_services.remove(service)

    new_cost = int(request_data["cost"])
    new_comment = request_data["comment"]

    if new_products:
        order.products = json.dumps(new_products)
    if new_services:
        order.services = json.dumps(new_services)
    if new_cost:
        order.cost = new_cost
    if new_comment:
        order.comment = new_comment

    db.session.commit()

    return redirect(url_for('new_orders'))

@app.route('/edit/<id>', methods=['GET'])
@login_required
def openEditForm(id):
    order= IncomingOrder.query.filter_by(id=id).first()

    # Если в созданных заказах нет, ищем в заказах в работе
    if not order:
        order = ProcessingOrder.query.filter_by(order_id=id).first()

    # Если в заказах в работе нет, ищем в завершенных заказах
    if not order:
        order = CompletedOrder.query.filter_by(order_id=id).first()

    products = order.get_products()
    services = order.get_services()

    return render_template("edit.html", order=order, products=products, services=services)
