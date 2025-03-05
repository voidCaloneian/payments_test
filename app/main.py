"""
REST API для работы с пользователями, их счетами и платежами.
Пользователи могут авторизоваться и просматривать свои счета и платежи.
Администраторы могут создавать, изменять и удалять пользователей.
Платежи обрабатываются через эмулированный Webhook.
"""

import uuid
import hashlib
from functools import wraps
from decimal import Decimal

from sanic import Sanic
from sanic.request import Request
from sanic.response import json as sanic_json
from sanic.exceptions import Unauthorized, NotFound, InvalidUsage

import jwt
from passlib.context import CryptContext

from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from app.config import SECRET_KEY
from app.db import engine, AsyncSessionLocal
from app.models import Base, User, Account, Payment

app = Sanic("REST_API_APP")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """
    Хеширование пароля
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверка пароля
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_token(user: User) -> str:
    """
    Создание JWT-токена
    """
    payload = {"user_id": user.id, "is_admin": user.is_admin}
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


async def get_current_user(request: Request):
    """
    Получение текущего пользователя из JWT-токена
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise Unauthorized("Missing authorization header")
    try:
        token = auth_header.split("Bearer ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(User).where(User.id == payload["user_id"])
            )
            user = result.scalars().first()
            if not user:
                raise Unauthorized("User not found")
            return user
    except Exception:
        raise Unauthorized("Invalid token")


def require_auth(handler):
    """
    Декоратор для проверки авторизации пользователя
    """

    @wraps(handler)
    async def decorated(request: Request, *args, **kwargs):
        request.ctx.user = await get_current_user(request)
        return await handler(request, *args, **kwargs)

    return decorated


def require_admin(handler):
    """
    Декоратор для проверки авторизации админа
    """

    @wraps(handler)
    async def decorated(request: Request, *args, **kwargs):
        user = await get_current_user(request)
        if not user.is_admin:
            raise Unauthorized("Admin access required")
        request.ctx.user = user
        return await handler(request, *args, **kwargs)

    return decorated


# Аутентификация пользователей и админов
@app.post("/auth/user/login")
async def user_login(request: Request):
    """
    Аутентификация пользователя
    """
    data = request.json
    if not data or "email" not in data or "password" not in data:
        raise InvalidUsage("Email and password required")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.email == data["email"], User.is_admin == False)
        )
        user = result.scalars().first()
        if not user or not verify_password(data["password"], user.password):
            raise Unauthorized("Invalid credentials")
        token = create_token(user)
        return sanic_json({"token": token})


@app.post("/auth/admin/login")
async def admin_login(request: Request):
    """
    Аутентификация админа
    """
    data = request.json
    if not data or "email" not in data or "password" not in data:
        raise InvalidUsage("Email and password required")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.email == data["email"], User.is_admin == True)
        )
        user = result.scalars().first()
        if not user or not verify_password(data["password"], user.password):
            raise Unauthorized("Invalid credentials")
        token = create_token(user)
        return sanic_json({"token": token})


# Эндпоинты для Пользователя
@app.get("/user/me")
@require_auth
async def get_user_info(request: Request):
    """
    Получение информации о пользователе
    """
    user: User = request.ctx.user
    return sanic_json({"id": user.id, "email": user.email, "full_name": user.full_name})


@app.get("/user/accounts")
@require_auth
async def get_user_accounts(request: Request):
    """
    Получение списка счетов пользователя
    """
    user: User = request.ctx.user
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Account).where(Account.user_id == user.id)
        )
        accounts = result.scalars().all()
        data = [{"id": acc.id, "balance": float(acc.balance)} for acc in accounts]
        return sanic_json(data)


@app.get("/user/payments")
@require_auth
async def get_user_payments(request: Request):
    """
    Получение списка платежей пользователя
    """
    user: User = request.ctx.user
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Payment).where(Payment.user_id == user.id)
        )
        payments = result.scalars().all()
        data = [
            {
                "id": p.id,
                "transaction_id": str(p.transaction_id),
                "account_id": p.account_id,
                "amount": float(p.amount),
            }
            for p in payments
        ]
        return sanic_json(data)


# Эндпоинты для Админов
@app.get("/admin/me")
@require_admin
async def get_admin_info(request: Request):
    """
    Получение информации об админе
    """
    admin: User = request.ctx.user
    return sanic_json(
        {"id": admin.id, "email": admin.email, "full_name": admin.full_name}
    )


@app.post("/admin/users")
@require_admin
async def create_user(request: Request):
    """
    Создание пользователя админом
    """
    data = request.json
    required_fields = {"email", "password", "full_name"}
    if not data or not required_fields.issubset(data):
        raise InvalidUsage("Missing fields")
    new_user = User(
        email=data["email"],
        full_name=data["full_name"],
        password=hash_password(data["password"]),
        is_admin=False,
    )
    async with AsyncSessionLocal() as session:
        session.add(new_user)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return sanic_json({"error": "User already exists"}, status=400)
    return sanic_json({"message": "User created", "user_id": new_user.id})


@app.put("/admin/users/<user_id:int>")
@require_admin
async def update_user(request: Request, user_id: int):
    """
    Обновление информации о пользователе админом
    """
    data = request.json
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.id == user_id, User.is_admin == False)
        )
        user = result.scalars().first()
        if not user:
            raise NotFound("User not found")
        if "email" in data:
            user.email = data["email"]
        if "full_name" in data:
            user.full_name = data["full_name"]
        if "password" in data:
            user.password = hash_password(data["password"])
        await session.commit()
        return sanic_json({"message": "User updated"})


@app.delete("/admin/users/<user_id:int>")
@require_admin
async def delete_user(request: Request, user_id: int):
    """
    Удаление пользователя админом
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.id == user_id, User.is_admin == False)
        )
        user = result.scalars().first()
        if not user:
            raise NotFound("User not found or cannot delete admin")
        await session.delete(user)
        await session.commit()
        return sanic_json({"message": "User deleted"})


@app.get("/admin/users")
@require_admin
async def list_users(request: Request):
    """
    Получение списка пользователей админом
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.is_admin == False))
        users = result.scalars().all()
        users_data = []
        for user in users:
            acc_result = await session.execute(
                select(Account).where(Account.user_id == user.id)
            )
            accounts = acc_result.scalars().all()
            accounts_data = [
                {"id": acc.id, "balance": float(acc.balance)} for acc in accounts
            ]
            users_data.append(
                {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "accounts": accounts_data,
                }
            )
        return sanic_json(users_data)


# Эндпоинт для обработки платежей (Webhook)
@app.post("/webhook/payment")
async def process_payment(request: Request):
    """
    Обработка платежей через **Webhook**
    """
    data = request.json
    required_fields = {"transaction_id", "user_id", "account_id", "amount", "signature"}
    if not data or not required_fields.issubset(data):
        raise InvalidUsage("Missing payment data")

    # Формирование строки для подписи: значения полей в алфавитном порядке + **SECRET_KEY**
    concat_str = f"{data['account_id']}{data['amount']}{data['transaction_id']}{data['user_id']}{SECRET_KEY}"
    computed_signature = hashlib.sha256(concat_str.encode()).hexdigest()
    if computed_signature != data["signature"]:
        return sanic_json({"error": "Invalid signature"}, status=400)

    async with AsyncSessionLocal() as session:
        # Проверка уникальности транзакции
        result = await session.execute(
            select(Payment).where(Payment.transaction_id == data["transaction_id"])
        )
        existing_payment = result.scalars().first()
        if existing_payment:
            return sanic_json({"message": "Payment already processed"})

        # Проверка существования счета (без использования передаваемого account_id для создания)
        result = await session.execute(
            select(Account).where(
                Account.id == data["account_id"], Account.user_id == data["user_id"]
            )
        )
        account = result.scalars().first()
        if not account:
            user_result = await session.execute(
                select(User).where(User.id == data["user_id"])
            )
            user = user_result.scalars().first()
            if not user:
                return sanic_json({"error": "User does not exist"}, status=400)
            # Не передаем id, чтобы избежать конфликта с auto-generated PK
            account = Account(user_id=data["user_id"], balance=0)
            session.add(account)
            await session.commit()

            # После коммита обновляем запрос для получения установленного id, если потребуется
            result = await session.execute(
                select(Account).where(Account.user_id == data["user_id"])
            )
            account = result.scalars().first()

        # Создание платежа и обновление баланса счета
        payment = Payment(
            transaction_id=uuid.UUID(data["transaction_id"]),
            account_id=account.id,
            user_id=data["user_id"],
            amount=Decimal(data["amount"]),
        )
        account.balance += Decimal(data["amount"])
        session.add(payment)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            return sanic_json({"error": "Failed to process payment"}, status=500)
        return sanic_json({"message": "Payment processed"})


async def setup_db():
    """
    Создание таблиц и тестовых данных
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Тестовый админ
        result = await session.execute(
            select(User).where(User.email == "admin@example.com")
        )
        admin = result.scalars().first()
        if not admin:
            admin = User(
                email="admin@example.com",
                full_name="Admin User",
                password=hash_password("adminpassword"),
                is_admin=True,
            )
            session.add(admin)

        # Тестовый Пользователь и счёт для него
        result = await session.execute(
            select(User).where(User.email == "user@example.com")
        )
        user = result.scalars().first()
        if not user:
            user = User(
                email="user@example.com",
                full_name="Test User",
                password=hash_password("userpassword"),
                is_admin=False,
            )
            session.add(user)
            await session.commit()  # чтобы получить user.id для создания счета
            test_account = Account(user_id=user.id, balance=100)
            session.add(test_account)
        await session.commit()


@app.listener("after_server_start")
async def on_after_server_start(app, loop):
    await setup_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, access_log=True)
