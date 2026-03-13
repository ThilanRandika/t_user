jest.mock('mongoose', () => {
  const actual = jest.requireActual('mongoose');
  return {
    ...actual,
    connect: jest.fn().mockResolvedValue(true),
  };
});

jest.mock('../models/User', () => {
  return {
    findOne: jest.fn().mockResolvedValue(null),
    create: jest.fn().mockResolvedValue({ 
      _id: '123', 
      name: 'Test User', 
      email: 'test@example.com',
      role: 'customer'
    }),
  };
});

// Suppress console.log for clean test output
console.log = jest.fn();

const request = require('supertest');
const app = require('../index');

describe('User Service APIs', () => {
  it('GET /health - should return 200 and health status', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('user-service');
  });

  it('GET /unknown - should return 404 for non-existent route', async () => {
    const res = await request(app).get('/unknown-route');
    expect(res.statusCode).toBe(404);
  });

  it('POST /auth/register - should return 400 for missing validation fields', async () => {
    const res = await request(app).post('/auth/register').send({});
    expect(res.statusCode).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  it('POST /auth/register - should return 201 for valid registration', async () => {
    const res = await request(app).post('/auth/register').send({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'password123'
    });
    expect(res.statusCode).toBe(201);
    expect(res.body.message).toBe('User registered successfully');
    expect(res.body.token).toBeDefined();
  });
});
