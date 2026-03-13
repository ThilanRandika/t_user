const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'User Auth Service API',
      version: '1.0.0',
      description:
        'Microservice responsible for user registration, authentication, and JWT token verification. Other services call /auth/verify to validate tokens.',
      contact: { name: 'ShopEase Team' },
    },
    servers: [{ url: 'http://localhost:3001', description: 'Local development' }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    tags: [{ name: 'Auth', description: 'Authentication endpoints' }],
  },
  apis: ['./src/routes/*.js'],
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = { swaggerSpec };
