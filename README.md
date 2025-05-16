# 🛠️ PDZ Backend API

  This is the backend API developed for PDZ, built using Spring Boot. It provides core services such as authentication, user authorization, data validation, and integration with a PostgreSQL database. The API **will** communicates with the frontend via RESTful endpoints and handles secure user sessions using JWT and **probably** OAuth2.
  
📦 Key Dependencies

| Dependency                          | Description                             |
| ----------------------------------- | --------------------------------------- |
| `spring-boot-starter-web`           | Builds RESTful web services             |
| `spring-boot-starter-security`      | Secures API endpoints                   |
| `spring-boot-starter-oauth2-client` | Enables OAuth2 login and client support |
| `spring-boot-starter-data-jpa`      | JPA integration for data persistence    |
| `io.jsonwebtoken:jjwt-*`            | JWT creation, parsing, and validation   |
| `org.postgresql:postgresql`         | PostgreSQL JDBC driver                  |
| `org.projectlombok:lombok`          | Reduces boilerplate with annotations    |

## Getting Started

1. **Clone the Repository**: 
   ```bash
   git clone
    ```
2. **Navigate to the Project Directory**:
    ```bash
    cd pdz-backend
    ```
   
3. **Create application.properties file in src/main/resources with the following content**:
    ```properties
    spring.application.name=pdz-api
    
    spring.jpa.defer-datasource-initialization=true
    spring.jpa.hibernate.ddl-auto=update
    
    spring.datasource.url=jdbc:mysql://localhost:3306/pdz
    spring.datasource.username=root
    spring.datasource.password=root
    spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
    
    pdz.api.jwtSecret=JWT_SECRET_KEY
    pdz.api.jwtExpirationMs=864000000
    
    
    spring.security.oauth2.client.registration.discord.client-id=YOUR_DISCORD_CLIENT_ID
    spring.security.oauth2.client.registration.discord.client-secret=YOUR_DISCORD_CLIENT_SECRET
    spring.security.oauth2.client.registration.discord.redirect-uri={baseUrl}/login/oauth2/code/discord
    spring.security.oauth2.client.registration.discord.authorization-grant-type=authorization_code
    spring.security.oauth2.client.registration.discord.scope=identify,email
    spring.security.oauth2.client.provider.discord.authorization-uri=https://discord.com/api/oauth2/authorize
    spring.security.oauth2.client.provider.discord.token-uri=https://discord.com/api/oauth2/token
    spring.security.oauth2.client.provider.discord.user-info-uri=https://discord.com/api/users/@me
    spring.security.oauth2.client.provider.discord.user-name-attribute=id
    ```
   
4. **Build the Project**:
    ```bash
    ./mvnw clean install
    ```
5. **Run the Application**:
    ```bash
    ./mvnw spring-boot:run
    ```
6. **Access the API**: Open your browser and navigate to `http://localhost:8080/api` to see the API in action.


## Discord OAuth2 Authentication

The application uses Discord OAuth2 for user authentication. Users can log in using their Discord accounts, and the application will handle the authentication flow, including token exchange and user information retrieval.

### Discord OAuth2 Endpoint

| Endpoint                         | Description                             |
| -------------------------------- | --------------------------------------- |
| `/oauth2/authorization/discord` | Initiates the OAuth2 login flow        |
