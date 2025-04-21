/**
 * PetCare Authentication Service
 * Handles user authentication, registration, and session management
 */

// Configuration
const API_URL = "http://localhost:8080/api"; // Update with your API URL
const DEBUG = false;
const TOKEN_NAME = "authToken";
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours

// Debug logging helper
function debugLog(...args) {
  if (DEBUG) {
    console.log(`[AUTH ${new Date().toISOString()}]`, ...args);
  }
}

// State tracking to prevent loops
let isProcessingAuth = false;
let lastAuthCheck = 0;
let redirectInProgress = false;
let authCheckInterval = null;

// ===== Token Management =====

/**
 * Get the authentication token from storage
 */
function getToken() {
  return localStorage.getItem(TOKEN_NAME) || sessionStorage.getItem(TOKEN_NAME);
}

/**
 * Save the authentication token to storage
 * @param {string} token - JWT token
 * @param {boolean} rememberMe - Whether to persist in localStorage
 */
function saveToken(token, rememberMe = false) {
  if (rememberMe) {
    localStorage.setItem(TOKEN_NAME, token);
    sessionStorage.removeItem(TOKEN_NAME);
  } else {
    sessionStorage.setItem(TOKEN_NAME, token);
    localStorage.removeItem(TOKEN_NAME);
  }
}

/**
 * Clear the authentication token from all storage
 */
function clearToken() {
  localStorage.removeItem(TOKEN_NAME);
  sessionStorage.removeItem(TOKEN_NAME);
}

/**
 * Parse JWT token to get user data
 * @param {string} token - JWT token
 * @returns {Object|null} Parsed token data or null if invalid
 */
function parseJwt(token) {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    debugLog("Error parsing JWT token:", error);
    return null;
  }
}

// ===== Authentication Functions =====

/**
 * Login user with username/password
 * @param {string} username - Username or email
 * @param {string} password - User password
 * @param {boolean} rememberMe - Whether to persist login
 * @returns {Promise<Object>} Login result
 */
async function login(username, password, rememberMe = false) {
  if (isProcessingAuth) {
    debugLog("Login already in progress, skipping");
    return { success: false, message: "Login already in progress" };
  }
  
  isProcessingAuth = true;
  debugLog("Starting login process for:", username);
  
  try {
    // Call login API from Spring Boot backend
    const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // Thêm để hỗ trợ CORS với allowCredentials
        body: JSON.stringify({ username: username, password }),
      });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || "Login failed");
    }

    const data = await response.json();
    const token = data.token; // Lấy token từ response

    // Save token based on "Remember Me" checkbox
    saveToken(token, rememberMe);

    // Get user info from token
    const userData = parseJwt(token);
    
    // Set flag to prevent multiple redirects  
    redirectInProgress = true;
    
    return { success: true, user: userData };

  } catch (error) {
    debugLog("Login error:", error);
    return { 
      success: false, 
      message: error.message || "Đăng nhập thất bại"
    };
  } finally {
    setTimeout(() => {
      isProcessingAuth = false;
    }, 500);
  }
}

/**
 * Register a new user
 * @param {Object} userData - User registration data
 * @returns {Promise<Object>} Registration result
 */
async function register(userData) {
  if (isProcessingAuth) {
    debugLog("Registration already in progress, skipping");
    return { success: false, message: "Registration already in progress" };
  }
  
  isProcessingAuth = true;
  debugLog("Starting registration process");
  
  try {
    // Validate required fields
    if (!userData.username && !userData.userName) {
      throw new Error("Username is required");
    }
    
    if (!userData.email) {
      throw new Error("Email is required");
    }
    
    if (!userData.password) {
      throw new Error("Password is required");
    }
    
    // Call register API from Spring Boot backend
    const response = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // Thêm để hỗ trợ CORS với allowCredentials
        body: JSON.stringify({
          username: userData.username, // Sử dụng userName để khớp với dữ liệu
          email: userData.email,
          phoneNumber: userData.phoneNumber || "",
          password: userData.password,
          confirmPassword: userData.confirmPassword || userData.password, // Thêm confirmPassword
        }),
      });
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.message || "Registration failed");
    }

    debugLog("Registration successful");
    return { success: true };
  } catch (error) {
    debugLog("Registration error:", error);
    return { success: false, message: error.message };
  } finally {
    // Reset processing flag after a short delay
    setTimeout(() => {
      isProcessingAuth = false;
    }, 500);
  }
}

/**
 * Logout the current user
 * @param {boolean} redirect - Whether to redirect after logout
 * @returns {void}
 */
function logout(redirect = true) {
  if (isProcessingAuth) {
    debugLog("Logout already in progress, skipping");
    return;
  }
  
  isProcessingAuth = true;
  debugLog("Starting logout process");
  
  // Clear token from storage
  clearToken();
  
  // Set flag to prevent multiple redirects
  if (redirect) {
    redirectInProgress = true;
    
    // Redirect after a short delay
    setTimeout(() => {
      window.location.href = "index.html";
    }, 100);
  }
  
  // Reset processing flag after a short delay
  setTimeout(() => {
    isProcessingAuth = false;
  }, 500);
}

/**
 * Check if user is authenticated
 * @returns {boolean} Authentication status
 */
function isAuthenticated() {
  const token = getToken();
  if (!token) return false;

  // Check if token is valid
  const userData = parseJwt(token);
  if (!userData) return false;

  // Check if token is expired
  const currentTime = Date.now() / 1000;
  if (userData.exp && userData.exp < currentTime) {
    clearToken();
    return false;
  }

  return true;
}

/**
 * Get current user data
 * @returns {Object|null} User data or null if not authenticated
 */
function getCurrentUser() {
  if (!isAuthenticated()) return null;
  
  const token = getToken();
  try {
    return parseJwt(token);
  } catch (error) {
    debugLog("Error getting current user:", error);
    logout(false); // Invalid token, log out without redirect
    return null;
  }
}

/**
 * Check if user has a specific role
 * @param {string} role - Role to check
 * @param {Object} userData - Optional user data (uses current user if not provided)
 * @returns {boolean} Whether user has the role
 */
function hasRole(role, userData = null) {
  const user = userData || getCurrentUser();
  if (!user) return false;

  // Check in authorities array
  if (user.authorities && Array.isArray(user.authorities)) {
    return user.authorities.some((auth) => 
      auth.authority === `ROLE_${role}` || auth.authority === role
    );
  }

  // Check role field
  if (user.role) {
    return user.role === role;
  }

  // Check in roles array if present
  if (user.roles && Array.isArray(user.roles)) {
    return user.roles.includes(role) || user.roles.includes(`ROLE_${role}`);
  }

  return false;
}

/**
 * Make an authenticated API request
 * @param {string} url - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
async function fetchWithAuth(url, options = {}) {
  const token = getToken();

  if (!token) {
    throw new Error("No authentication token");
  }

  const headers = {
    ...options.headers,
    Authorization: `Bearer ${token}`,
  };

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      // Invalid or expired token
      logout();
      throw new Error("Session expired");
    }

    return response;
  } catch (error) {
    debugLog("API error:", error);
    throw error;
  }
}

// ===== UI Management =====

/**
 * Helper function to safely add event listeners without duplication
 * @param {Element} element - DOM element
 * @param {string} eventType - Event type (e.g., 'click')
 * @param {Function} handler - Event handler function
 */
function addSingleEventListener(element, eventType, handler) {
  if (!element || !element.addEventListener) return;
  
  // Remove existing listeners first
  if (element._originalHandler && element._originalHandler[eventType]) {
    element.removeEventListener(eventType, element._originalHandler[eventType], false);
  }
  
  // Store and add new listener
  if (!element._originalHandler) element._originalHandler = {};
  element._originalHandler[eventType] = handler;
  
  element.addEventListener(eventType, handler, false);
}

/**
 * Update UI elements based on authentication state
 */
function updateAuthUI() {
  debugLog("Updating auth UI");
  
  const isLoggedIn = isAuthenticated();
  const user = getCurrentUser();

  // Add authentication classes to body
  document.body.classList.toggle('authenticated', isLoggedIn);
  document.body.classList.toggle('not-authenticated', !isLoggedIn);
  
  if (isLoggedIn && user) {
    document.body.classList.toggle('is-admin', hasRole('ADMIN', user));
  } else {
    document.body.classList.remove('is-admin');
  }

  // Update specific elements if they exist
  const loginButtons = document.querySelectorAll(".login-button, .register-button");
  const userInfo = document.querySelectorAll(".user-info");
  const userNameElements = document.querySelectorAll("[data-user-name]");
  const logoutButtons = document.querySelectorAll(".logout-btn");
  const adminLinks = document.querySelectorAll(".admin-link");

  if (isLoggedIn && user) {
    // User is logged in
    loginButtons.forEach((el) => (el.style.display = "none"));
    userInfo.forEach((el) => (el.style.display = "block"));
    userNameElements.forEach((el) => (el.textContent = user.sub || user.username || "User"));

    // Only add event listeners once
    logoutButtons.forEach((el) => {
      el.style.display = "block";
      addSingleEventListener(el, "click", (e) => {
        e.preventDefault();
        logout();
      });
    });

    // Show admin link if user has admin role
    if (hasRole("ADMIN", user)) {
      adminLinks.forEach((el) => (el.style.display = "block"));
    } else {
      adminLinks.forEach((el) => (el.style.display = "none"));
    }
  } else {
    // User is not logged in
    loginButtons.forEach((el) => (el.style.display = "block"));
    userInfo.forEach((el) => (el.style.display = "none"));
    logoutButtons.forEach((el) => (el.style.display = "none"));
    adminLinks.forEach((el) => (el.style.display = "none"));
  }
}

/**
 * Check if redirection is needed based on current page and auth status
 */
function checkAuthRedirect() {
  // Skip if redirection is already in progress
  if (redirectInProgress) {
    debugLog("Redirection already in progress, skipping check");
    return;
  }
  
  // Throttle checks to prevent excessive processing
  const now = Date.now();
  if (now - lastAuthCheck < 1000) { // Only check once per second at most
    return;
  }
  lastAuthCheck = now;
  
  const currentPath = window.location.pathname;
  debugLog("Checking auth redirect for path:", currentPath);
  
  const isLoggedIn = isAuthenticated();
  const isAdmin = isLoggedIn && hasRole("ADMIN");
  
  // Admin page protection
  if (currentPath.includes('admin.html')) {
    if (!isLoggedIn) {
      debugLog("Not authenticated, redirecting to login");
      redirectInProgress = true;
      window.location.href = "login.html";
      return;
    }

    if (!isAdmin) {
      debugLog("Not admin, redirecting to home");
      redirectInProgress = true;
      window.location.href = "index.html";
      return;
    }
    
    debugLog("User is admin, staying on admin page");
  } 
  // Login page redirect if already logged in
  else if (currentPath.includes('login.html') && isLoggedIn) {
    if (isAdmin) {
      debugLog("Already authenticated as admin, redirecting to admin");
      redirectInProgress = true;
      window.location.href = "admin.html";
      return;
    } else {
      debugLog("Already authenticated, redirecting to home");
      redirectInProgress = true;
      window.location.href = "index.html";
      return;
    }
  }
  
  debugLog("No redirection needed");
}

/**
 * Initialize authentication system
 */
function initAuth() {
  debugLog("Initializing auth system");
  
  // Update UI based on current auth state
  updateAuthUI();
  
  // Check if redirection is needed
  checkAuthRedirect();
  
  // Set up periodic auth check (every 5 minutes)
  if (authCheckInterval) {
    clearInterval(authCheckInterval);
  }
  
  authCheckInterval = setInterval(() => {
    if (isAuthenticated()) {
      updateAuthUI();
    } else {
      // If token has expired, update UI and redirect if needed
      updateAuthUI();
      checkAuthRedirect();
    }
  }, 5 * 60 * 1000);
  
  // Reset redirection flag when page load is complete
  window.addEventListener('load', function() {
    redirectInProgress = false;
    debugLog("Page fully loaded, reset redirection flag");
  });
}

// Initialize on DOM content loaded
document.addEventListener("DOMContentLoaded", initAuth);

// Export the auth service
window.authService = {
  login,
  register,
  logout,
  isAuthenticated,
  getCurrentUser,
  hasRole,
  fetchWithAuth,
  updateAuthUI,
  checkAuthRedirect,
  initAuth
};