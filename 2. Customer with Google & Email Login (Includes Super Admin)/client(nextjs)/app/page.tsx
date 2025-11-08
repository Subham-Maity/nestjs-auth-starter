'use client';

import {useState, useEffect, JSX} from 'react';

interface User {
  id?: string;
  email?: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  role?: string;
  img?: string;
  [key: string]: any;
}

export default function GoogleAuthTest(): JSX.Element {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [checkingAuth, setCheckingAuth] = useState<boolean>(true);

  const API_URL = 'http://localhost:3336/xam';

  useEffect(() => {
    void checkAuthStatus();
  }, []);

  const checkAuthStatus = async (): Promise<void> => {
    try {
      const response = await fetch(`${API_URL}/auth/me`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const userData: User = await response.json();
        setUser(userData);
      }
    } catch (err) {
      console.error('Not authenticated:', err);
    } finally {
      setCheckingAuth(false);
    }
  };

  const handleGoogleLogin = (): void => {
    setLoading(true);
    setError('');
    window.location.href = `${API_URL}/auth/customer/login/google`;
  };

  const handleLogout = async (): Promise<void> => {
    try {
      setLoading(true);
      const response = await fetch(`${API_URL}/auth/logout/customer`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        setUser(null);
        setError('');
      } else {
        setError('Logout failed');
      }
    } catch (err) {
      if (err instanceof Error) {
        setError(`Logout error: ${err.message}`);
      } else {
        setError('Unknown logout error');
      }
    } finally {
      setLoading(false);
    }
  };

  if (checkingAuth) {
    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-xl p-8 max-w-md w-full">
            <div className="flex flex-col items-center space-y-4">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
              <p className="text-gray-600">Checking authentication...</p>
            </div>
          </div>
        </div>
    );
  }

  return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-xl p-8 max-w-md w-full">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-100 rounded-full mb-4">
              <svg
                  className="w-8 h-8 text-indigo-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
              >
                <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Google Auth Test
            </h1>
            <p className="text-gray-600">Test Google OAuth authentication</p>
          </div>

          {error && (
              <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-center">
                  <svg
                      className="w-5 h-5 text-red-600 mr-2"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                  >
                    <path
                        fillRule="evenodd"
                        d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                        clipRule="evenodd"
                    />
                  </svg>
                  <span className="text-red-800 text-sm">{error}</span>
                </div>
              </div>
          )}

          {!user ? (
              <div className="space-y-4">
                <button
                    onClick={handleGoogleLogin}
                    disabled={loading}
                    className="w-full flex items-center justify-center space-x-3 px-6 py-3 bg-white border-2 border-gray-300 rounded-lg hover:border-indigo-500 hover:shadow-md transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-indigo-600"></div>
                  ) : (
                      <>
                        <svg className="w-5 h-5" viewBox="0 0 24 24">
                          <path
                              fill="#4285F4"
                              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                          />
                          <path
                              fill="#34A853"
                              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                          />
                          <path
                              fill="#FBBC05"
                              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                          />
                          <path
                              fill="#EA4335"
                              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                          />
                        </svg>
                        <span className="text-gray-700 font-medium">
                    Continue with Google
                  </span>
                      </>
                  )}
                </button>

                <div className="relative my-6">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                <span className="px-4 bg-white text-gray-500">
                  API Endpoint Info
                </span>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-4 space-y-2">
                  <div className="flex items-start space-x-2">
                    <svg
                        className="w-5 h-5 text-indigo-600 mt-0.5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                      <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <div className="flex-1">
                      <p className="text-xs font-semibold text-gray-700 mb-1">
                        Google Login URL:
                      </p>
                      <code className="text-xs text-gray-600 break-all">
                        GET {API_URL}/auth/customer/login/google
                      </code>
                    </div>
                  </div>
                  <div className="flex items-start space-x-2">
                    <svg
                        className="w-5 h-5 text-indigo-600 mt-0.5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                      <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <div className="flex-1">
                      <p className="text-xs font-semibold text-gray-700 mb-1">
                        Callback URL:
                      </p>
                      <code className="text-xs text-gray-600 break-all">
                        GET {API_URL}/auth/customer/google/callback
                      </code>
                    </div>
                  </div>
                </div>
              </div>
          ) : (
              <>
                <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
                  <div className="flex items-center mb-3">
                    <svg
                        className="w-6 h-6 text-green-600 mr-2"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                      <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <span className="text-green-800 font-semibold">
                  Authentication Successful!
                </span>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-6 space-y-4">
                  <h3 className="font-semibold text-gray-900 mb-4">User Details</h3>

                  {user.img && (
                      <div className="flex justify-center mb-4">
                        <img
                            src={user.img}
                            alt="Profile"
                            className="w-20 h-20 rounded-full border-4 border-white shadow-lg"
                        />
                      </div>
                  )}

                  <div className="space-y-3">
                    {Object.entries(user).map(([key, value]) =>
                        typeof value === 'string' ? (
                            <div key={key}>
                              <label className="text-xs font-semibold text-gray-500 uppercase">
                                {key}
                              </label>
                              <p className="text-sm text-gray-900 bg-white p-2 rounded border border-gray-200 break-all">
                                {value}
                              </p>
                            </div>
                        ) : null
                    )}
                  </div>
                </div>

                <button
                    onClick={handleLogout}
                    disabled={loading}
                    className="w-full px-6 py-3 mt-6 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors duration-200 font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                      <div className="flex items-center justify-center">
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                      </div>
                  ) : (
                      'Logout'
                  )}
                </button>
              </>
          )}
        </div>
      </div>
  );
}
