
## Запуск проекта

  

### С Docker Compose
```bash
docker compose up --build
```
### Без Docker Compose
```bash
pip install -r requirements.txt
```
Далее создаём базу данных ```app_db```  и пользователя через psql:
```psql
CREATE DATABASE app_db;
CREATE USER app_user WITH ENCRYPTED PASSWORD 'app_password';
GRANT ALL PRIVILEGES ON DATABASE app_db TO app_user;`
```
После запускаем само приложение командой
```bash
python -m app.main
```
Приложение будет доступно по адресу:
**http://localhost:8000**

## Тестовые данные:
-   **Пользователь:**
    -   **Email:**  user@example.com
    -   **Password:**  userpassword
-   **Администратор:**
    -   **Email:**  admin@example.com
    -   **Password:**  adminpassword
   
## Эндпоинты

### Аутентификация

-   **POST /auth/user/login**  
    Аутентификация **пользователя**.  
    **Тело запроса (JSON):**
    ``` json
    {
	    "email":  "user@example.com",  
	    "password":  "userpassword"
	}
	```
	**POST /auth/admin/login**  
Аутентификация **админа**.  
**Тело запроса (JSON):**
    ```json
    {
	     "email": "admin@example.com",
	     "password": "adminpassword"
    }
    ```
    
### Webhook Обработки платежа

-   **POST /webhook/payment**
    Обработка платежей
    **Тело запроса (JSON):**
  ```json
  {
  	"transaction_id": "5eae174f-7cd0-472c-bd36-35660f00132b",
  	"user_id": 1,
  	"account_id": 1,
  	"amount": 100,
  	"signature": "7b47e41efe564a062029da3367bde8844bea0fb049f894687cee5d57f2858bc8"
  }
  ```

### **Пользователь**
 #### ! Каждый Эндпоинт требует указанного JWT Токена в заголовках !
 **Заголовок:**  
    `Authorization: Bearer <JWT-токен>`

-   **GET /user/me**  
    Получение данных о  **пользователе**  (id, email, full_name).  
-   **GET /user/accounts**  
    Получение списка  **счетов**  пользователя с балансами.
-   **GET /user/payments**  
    Получение списка  **платежей**  пользователя.

### **Админ**
 #### ! Каждый Эндпоинт требует указанного JWT Токена в заголовках !
 **Заголовок:**  
    `Authorization: Bearer <JWT-токен>`

-   **GET /admin/me**  
    Получение данных об  **Админе**  (id, email, full_name).  
-   **POST /admin/users**  
    Создание нового  **пользователя**.  
    **Тело запроса (JSON):**
    ```json
    {
      "email": "newuser@example.com",
      "password": "newuserpassword",
      "full_name": "New User"
    }
    ```
-   **PUT /admin/users/<user_id>**  
    Обновление данных  **пользователя**.  
    **Тело запроса (JSON):**
    
    ```json
    {
      "email": "updated@example.com",
      "full_name": "Updated Name",
      "password": "newpassword"
    }
    ```
    
-   **DELETE /admin/users/<user_id>**  
    Удаление  **пользователя**.
-   **GET /admin/users**  
    Получение списка всех  **пользователей**  с их  **счетами**  и балансами.
