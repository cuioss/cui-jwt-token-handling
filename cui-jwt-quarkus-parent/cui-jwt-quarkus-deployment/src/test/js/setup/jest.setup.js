/**
 * Jest global setup file
 *
 * This file is executed before all tests run and sets up global mocks
 * and environment configurations for the test suite.
 */

// Mock global console methods to reduce test noise
global.console = {
  ...console,
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

// Mock window object properties commonly used in DevUI components
Object.defineProperty(window, 'location', {
  value: {
    href: 'http://localhost:8080/q/dev-ui',
    hostname: 'localhost',
    port: '8080',
    protocol: 'http:',
    pathname: '/q/dev-ui',
  },
  writable: true,
});

// Mock fetch API for HTTP requests
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    headers: new Headers(),
  })
);

// Mock customElements registry for web components
const definedElements = new Map();
global.customElements = {
  define: jest.fn((name, constructor) => {
    definedElements.set(name, constructor);
  }),
  get: jest.fn(name => definedElements.get(name)),
  whenDefined: jest.fn(() => Promise.resolve()),
};

// Mock DevUI global variables that might be injected by Quarkus
global.devUI = {
  jsonRPC: {
    CuiJwtDevUI: {
      getValidationStatus: jest.fn(() =>
        Promise.resolve({
          enabled: false,
          validatorPresent: false,
          status: 'BUILD_TIME',
          statusMessage: 'JWT validation status will be available at runtime',
        })
      ),
      getJwksStatus: jest.fn(() =>
        Promise.resolve({
          status: 'BUILD_TIME',
          message: 'JWKS endpoint status will be available at runtime',
        })
      ),
      getConfiguration: jest.fn(() =>
        Promise.resolve({
          enabled: false,
          healthEnabled: false,
          buildTime: true,
          message: 'Configuration details will be available at runtime',
        })
      ),
      validateToken: jest.fn(() =>
        Promise.resolve({
          valid: false,
          error: 'Token validation not available at build time',
        })
      ),
      getHealthInfo: jest.fn(() =>
        Promise.resolve({
          configurationValid: true,
          tokenValidatorAvailable: false,
          securityCounterAvailable: false,
          overallStatus: 'BUILD_TIME',
          message: 'Health information will be available at runtime',
        })
      ),
    },
  },
};

// Mock CSS custom properties for styling tests
document.documentElement.style.setProperty('--lumo-base-color', '#ffffff');
document.documentElement.style.setProperty('--lumo-contrast-10pct', 'rgba(0, 0, 0, 0.1)');
document.documentElement.style.setProperty('--lumo-primary-color', '#1976d2');
document.documentElement.style.setProperty('--lumo-success-color', '#4caf50');
document.documentElement.style.setProperty('--lumo-error-color', '#f44336');
document.documentElement.style.setProperty('--lumo-warning-color', '#ff9800');
