import React, { useState, useEffect, useRef } from 'react';

interface User {
  id: number;
  email: string;
}

interface PasswordEntry {
  id: number;
  website: string;
  username: string;
  password: string;
  created_at: string;
  tags: string;
}

const API_BASE = window.location.origin;

export const App: React.FC = () => {
  const [screen, setScreen] = useState<'login' | 'register' | 'app'>('login');
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
  const [allPasswords, setAllPasswords] = useState<PasswordEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [newWebsite, setNewWebsite] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [showGeneratedPassword, setShowGeneratedPassword] = useState(false);
  const [passwordLength, setPasswordLength] = useState(16);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error' | 'info'>('info');
  const [favorites, setFavorites] = useState<number[]>([]);
  const [visiblePasswords, setVisiblePasswords] = useState<{[key: number]: boolean}>({});
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [editingPasswordId, setEditingPasswordId] = useState<number | null>(null);
  const [deleteTargetId, setDeleteTargetId] = useState<number | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deletePromptTitle, setDeletePromptTitle] = useState('');
  const [deletePromptText, setDeletePromptText] = useState('');

  const toastTimer = useRef<NodeJS.Timeout | null>(null);

  // Load data from localStorage on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    const savedTheme = localStorage.getItem('theme') as 'dark' | 'light' | null;
    const savedFavorites = localStorage.getItem('favorites');

    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
      setScreen('app');
    }

    if (savedTheme) {
      setTheme(savedTheme);
    }

    if (savedFavorites) {
      setFavorites(JSON.parse(savedFavorites));
    }
  }, []);

  // Apply theme
  useEffect(() => {
    if (theme === 'dark') {
      document.body.className = 'text-gray-200 bg-gradient-to-br from-[#0F1E2E] via-slate-900 to-[#0F1E2E]';
    } else {
      document.body.className = 'text-gray-900 bg-gray-100';
    }
  }, [theme]);

  // Load passwords when token changes
  useEffect(() => {
    if (token) {
      loadPasswords();
    }
  }, [token]);

  // Filter passwords when search query or allPasswords change
  useEffect(() => {
    filterPasswords();
  }, [searchQuery, allPasswords]);

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    // Clear previous timer
    if (toastTimer.current) {
      clearTimeout(toastTimer.current);
      toastTimer.current = null;
    }

    setToastMessage(message);
    setToastType(type);

    // Auto hide toast after 3 seconds
    toastTimer.current = setTimeout(() => {
      setToastMessage('');
      toastTimer.current = null;
    }, 3000);
  };

  const register = async () => {
    if (!email || !password) {
      showToast('Please fill in all fields', 'error');
      return;
    }

    if (!validateEmail(email)) {
      showToast('Invalid email format', 'error');
      return;
    }

    if (!validatePasswordPolicy(password)) {
      showToast('Password too weak (≥8 & 3 types)', 'error');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (res.ok) {
        const data = await res.json();
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setScreen('app');
        setEmail('');
        setPassword('');
        showToast('Registration successful!', 'success');
      } else {
        const error = await res.json();
        showToast('Registration failed: ' + error.error, 'error');
      }
    } catch (e: any) {
      showToast('Error: ' + e.message, 'error');
    }
  };

  const login = async () => {
    if (!email || !password) {
      showToast('Please fill in all fields', 'error');
      return;
    }

    if (!validateEmail(email)) {
      showToast('Invalid email format', 'error');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok && data.token) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setScreen('app');
        setEmail('');
        setPassword('');
        showToast('Login successful!', 'success');
      } else {
        showToast('Login failed: ' + (data.error || 'Unknown'), 'error');
      }
    } catch (e: any) {
      showToast('Error: ' + e.message, 'error');
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    setPasswords([]);
    setScreen('login');
    setEmail('');
    setPassword('');
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  const loadPasswords = async () => {
    if (!token) return;

    try {
      const res = await fetch(`${API_BASE}/api/passwords`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok) {
        const data = await res.json();
        setAllPasswords(data);
      }
    } catch (e: any) {
      console.error('Failed to load passwords:', e);
      showToast('Failed to load passwords', 'error');
    }
  };

  const filterPasswords = () => {
    const query = searchQuery.toLowerCase();
    const filtered = allPasswords.filter(p => 
      p.website.toLowerCase().includes(query)
    );
    setPasswords(filtered);
  };

  const calculatePasswordStrength = (pwd: string) => {
    let strength = 0;
    if (pwd.length >= 8) strength++;
    if (pwd.length >= 12) strength++;
    if (pwd.length >= 16) strength++;
    if (/[a-z]/.test(pwd)) strength++;
    if (/[A-Z]/.test(pwd)) strength++;
    if (/[0-9]/.test(pwd)) strength++;
    if (/[^a-zA-Z0-9]/.test(pwd)) strength++;

    if (strength <= 2) return { level: 'weak', color: 'red', text: 'Weak' };
    if (strength <= 5) return { level: 'medium', color: 'yellow', text: 'Medium' };
    return { level: 'strong', color: 'green', text: 'Strong' };
  };

  const validateEmail = (email: string) => {
    return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
  };

  const validatePasswordPolicy = (pwd: string) => {
    const categories = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].reduce((a, r) => a + (r.test(pwd) ? 1 : 0), 0);
    return pwd.length >= 8 && categories >= 3;
  };

  const generatePassword = () => {
    let chars = '';
    if (includeUppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeLowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (includeNumbers) chars += '0123456789';
    if (includeSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (chars.length === 0) {
      showToast('Please select at least one character type', 'error');
      return;
    }

    let pwd = '';
    for (let i = 0; i < passwordLength; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setGeneratedPassword(pwd);
    setShowGeneratedPassword(false);
  };

  const savePassword = async () => {
    const website = newWebsite.trim();
    const password = newPassword.trim();
    const username = newUsername.trim();

    if (!website || !password) {
      showToast('Please fill in website and password', 'error');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/passwords`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ website, username, tags: [], password })
      });

      if (res.ok) {
        const data = await res.json();
        setNewWebsite('');
        setNewUsername('');
        setNewPassword('');
        setGeneratedPassword('');
        await loadPasswords();
        showToast('Password saved successfully!', 'success');
      } else {
        const error = await res.json();
        showToast('Failed to save password: ' + error.error, 'error');
      }
    } catch (e: any) {
      showToast('Error saving password: ' + e.message, 'error');
    }
  };

  const deletePassword = (id: number) => {
    setDeleteTargetId(id);
    setDeletePromptTitle('Confirm Deletion');
    setDeletePromptText('This action will permanently remove this password entry.');
    setShowDeleteConfirm(true);
  };

  const confirmDelete = async () => {
    if (!token) return;

    try {
      if (deleteTargetId) {
        const res = await fetch(`${API_BASE}/api/passwords/${deleteTargetId}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (res.ok) {
          await loadPasswords();
          showToast('Password deleted successfully!', 'success');
        } else {
          showToast('Failed to delete password', 'error');
        }
      } else if (selectedIds.length > 0) {
        // Bulk delete
        const promises = selectedIds.map(id => 
          fetch(`${API_BASE}/api/passwords/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
          })
        );

        await Promise.all(promises);
        await loadPasswords();
        clearSelection();
        showToast('Selected passwords deleted!', 'success');
      }
    } catch (e: any) {
      showToast('Error deleting password(s): ' + e.message, 'error');
    }

    setShowDeleteConfirm(false);
    setDeleteTargetId(null);
  };

  const cancelDelete = () => {
    setShowDeleteConfirm(false);
    setDeleteTargetId(null);
  };

  const startEditPassword = (id: number, website: string, password: string, username: string = '') => {
    setEditingPasswordId(id);
    setNewWebsite(website);
    setNewPassword(password);
    setNewUsername(username);
  };

  const updatePassword = async () => {
    if (!token || !editingPasswordId) return;

    const website = newWebsite.trim();
    const password = newPassword.trim();
    const username = newUsername.trim();

    if (!website || !password) {
      showToast('Please fill in website and password', 'error');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/passwords/${editingPasswordId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ website, username, tags: [], password })
      });

      if (res.ok) {
        setNewWebsite('');
        setNewUsername('');
        setNewPassword('');
        setEditingPasswordId(null);
        await loadPasswords();
        showToast('Password updated successfully!', 'success');
      } else {
        showToast('Failed to update password', 'error');
      }
    } catch (e: any) {
      showToast('Error updating password: ' + e.message, 'error');
    }
  };

  const cancelEdit = () => {
    setEditingPasswordId(null);
    setNewWebsite('');
    setNewUsername('');
    setNewPassword('');
  };

  const toggleFavorite = (id: number) => {
    const newFavorites = [...favorites];
    const index = newFavorites.indexOf(id);
    
    if (index > -1) {
      newFavorites.splice(index, 1);
    } else {
      newFavorites.push(id);
    }
    
    setFavorites(newFavorites);
    localStorage.setItem('favorites', JSON.stringify(newFavorites));
  };

  const toggleSelect = (id: number) => {
    const newSelectedIds = [...selectedIds];
    const index = newSelectedIds.indexOf(id);
    
    if (index > -1) {
      newSelectedIds.splice(index, 1);
    } else {
      newSelectedIds.push(id);
    }
    
    setSelectedIds(newSelectedIds);
  };

  const clearSelection = () => {
    setSelectedIds([]);
  };

  const bulkDelete = () => {
    if (selectedIds.length === 0) return;
    setDeleteTargetId(null);
    setDeletePromptTitle('Confirm Bulk Deletion');
    setDeletePromptText(`This will delete ${selectedIds.length} selected password(s). This action cannot be undone.`);
    setShowDeleteConfirm(true);
  };

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const getPasswordAge = (createdAt: string) => {
    const days = Math.floor((Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60 * 24));
    if (days > 90) return { text: `${days} days old`, color: 'red', warning: true };
    if (days > 60) return { text: `${days} days old`, color: 'yellow', warning: true };
    return { text: `${days} days old`, color: 'green', warning: false };
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard!', 'success');
    });
  };

  const togglePasswordVisibility = (id: number) => {
    setVisiblePasswords(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const toggleGeneratedPasswordVisibility = () => {
    setShowGeneratedPassword(!showGeneratedPassword);
  };

  const useGeneratedPassword = () => {
    setNewPassword(generatedPassword);
    copyToClipboard(generatedPassword);
    showToast('Generated password copied to clipboard!', 'success');
  };

  const exportPasswords = () => {
    const data = JSON.stringify(allPasswords, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `passwords-backup-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Passwords exported!', 'success');
  };

  const renderLoginScreen = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-6">
      <div className="bg-slate-800 border border-purple-500 rounded-lg p-8 shadow-2xl max-w-md w-full">
        <h1 className="text-4xl font-bold text-white mb-2 text-center">🔐 PassFortress</h1>
        <p className="text-purple-300 text-center mb-8">Secure Password Manager</p>
        <div className="space-y-4">
          <input 
            type="email" 
            placeholder="Email" 
            className="w-full bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500" 
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input 
            type="password" 
            placeholder="Password" 
            className="w-full bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500" 
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button 
            onClick={login}
            className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-bold py-3 px-6 rounded-lg transition"
          >
            🔓 Login
          </button>
          <button 
            onClick={() => setScreen('register')}
            className="w-full bg-slate-700 hover:bg-slate-600 text-white font-bold py-3 px-6 rounded-lg transition"
          >
            ✍️ Create Account
          </button>
        </div>
      </div>
    </div>
  );

  const renderRegisterScreen = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-6">
      <div className="bg-slate-800 border border-purple-500 rounded-lg p-8 shadow-2xl max-w-md w-full">
        <h1 className="text-4xl font-bold text-white mb-2 text-center">🔐 PassFortress</h1>
        <p className="text-purple-300 text-center mb-8">Create Your Account</p>
        <div className="space-y-4">
          <input 
            type="email" 
            placeholder="Email" 
            className="w-full bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500" 
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input 
            type="password" 
            placeholder="Password" 
            className="w-full bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500" 
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button 
            onClick={register}
            className="w-full bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg transition"
          >
            ✅ Register
          </button>
          <button 
            onClick={() => setScreen('login')}
            className="w-full bg-slate-700 hover:bg-slate-600 text-white font-bold py-3 px-6 rounded-lg transition"
          >
            🔓 Back to Login
          </button>
        </div>
      </div>
    </div>
  );

  const renderAppScreen = () => {
    const strength = generatedPassword ? calculatePasswordStrength(generatedPassword) : null;
    const sortedPasswords = [...passwords].sort((a, b) => {
      const aFav = favorites.includes(a.id);
      const bFav = favorites.includes(b.id);
      if (aFav && !bFav) return -1;
      if (!aFav && bFav) return 1;
      return 0;
    });

    return (
      <div className="min-h-screen p-6">
        <div className="max-w-5xl mx-auto">
          {/* Header */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
            <div>
              <h1 className="text-3xl sm:text-4xl font-bold text-white mb-1">🔐 PassFortress</h1>
              <p className="text-gray-400 text-xs sm:text-sm">
                Welcome, <span className="text-[#F48120] font-semibold">{user?.email}</span>
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button 
                onClick={toggleTheme}
                className="icon-btn btn-hover bg-slate-700 hover:bg-slate-600 text-white py-2 px-3 rounded-lg transition"
                title="Toggle Theme"
              >
                {theme === 'dark' ? '☀️' : '🌙'}
              </button>
              <button 
                onClick={exportPasswords}
                className="icon-btn btn-hover bg-blue-600 hover:bg-blue-700 text-white py-2 px-3 rounded-lg transition"
                title="Export"
              >
                📦
              </button>
              <button 
                onClick={logout}
                className="icon-btn btn-hover bg-red-600 hover:bg-red-700 text-white py-2 px-3 rounded-lg transition"
                title="Logout"
              >
                🚪
              </button>
            </div>
          </div>

          <div className="flex flex-col lg:flex-row gap-6">
            {/* Left: Search & Passwords List */}
            <div className="flex-1 space-y-6">
              <div className="bg-slate-800 border border-purple-500 rounded-lg p-6 shadow-2xl h-full">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-2xl font-bold text-white">🔑 Saved Passwords ({passwords.length})</h2>
                  <div className="flex items-center gap-2">
                    {selectedIds.length > 0 ? (
                      <>
                        <span className='text-xs text-gray-300'>Selected {selectedIds.length}</span>
                        <button 
                          onClick={clearSelection}
                          className="bg-slate-600 hover:bg-slate-500 text-white px-3 py-1 rounded text-xs"
                          title="Clear Selection"
                        >
                          🧹
                        </button>
                        <button 
                          onClick={bulkDelete}
                          className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-xs"
                          title="Delete Selected"
                          disabled={selectedIds.length === 0}
                          style={selectedIds.length === 0 ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
                        >
                          🗑️
                        </button>
                      </>
                    ) : null}
                  </div>
                </div>
                
                <input 
                  type="text" 
                  placeholder="🔍 Search passwords..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500 mb-4" 
                />
                
                <div className="space-y-3 max-h-[560px] overflow-y-auto pr-1">
                  {passwords.length === 0 ? (
                    <p className="text-gray-400 text-center py-8">No passwords saved yet.</p>
                  ) : (
                    sortedPasswords.map(p => {
                      const age = getPasswordAge(p.created_at);
                      const isFavorite = favorites.includes(p.id);
                      return (
                        <div 
                          key={p.id}
                          className="password-item bg-slate-700 p-4 rounded-lg border transition-all"
                          style={{ borderColor: isFavorite ? '#f59e0b' : '#8b5cf6' }}
                        >
                          <div className="flex justify-between items-start mb-2">
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <input 
                                  type="checkbox" 
                                  onChange={() => toggleSelect(p.id)}
                                  checked={selectedIds.includes(p.id)}
                                  className="accent-[#F48120] w-4 h-4" 
                                  title="Select"
                                />
                                <button 
                                  onClick={() => toggleFavorite(p.id)}
                                  className="text-2xl"
                                  title={isFavorite ? "Remove from favorites" : "Add to favorites"}
                                >
                                  {isFavorite ? '⭐' : '☆'}
                                </button>
                                <p 
                                  className="font-bold text-purple-300 text-lg truncate max-w-[180px]" 
                                  title={p.website}
                                >
                                  {p.website}
                                </p>
                              </div>
                              <p className="text-sm text-gray-400 font-mono ml-8 break-all">
                                {visiblePasswords[p.id] ? p.password : '••••••••••••'}
                              </p>
                              {p.username ? (
                                <p className='text-xs text-blue-300 ml-8 break-all'>👤 {p.username}</p>
                              ) : null}
                              <div className="flex items-center gap-3 mt-2 ml-8">
                                <p className="text-xs text-gray-500">
                                  📅 {new Date(p.created_at).toLocaleDateString()}
                                </p>
                                <p 
                                  className="text-xs" 
                                  style={{ color: age.color === 'red' ? '#f87171' : age.color === 'yellow' ? '#facc15' : '#4ade80' }}
                                >
                                  {age.warning ? '⚠️ ' : ''}{age.text}
                                </p>
                              </div>
                            </div>
                            <div className="flex flex-wrap gap-1">
                              <button 
                                onClick={() => togglePasswordVisibility(p.id)}
                                className="bg-purple-600 hover:bg-purple-700 text-white px-2 py-1.5 rounded-lg transition text-xs"
                                title={visiblePasswords[p.id] ? "Hide" : "Show"}
                              >
                                {visiblePasswords[p.id] ? '👁️' : '🔒'}
                              </button>
                              <button 
                                onClick={() => copyToClipboard(p.password)}
                                className="bg-blue-600 hover:bg-blue-700 text-white px-2 py-1.5 rounded-lg transition text-xs"
                                title="Copy"
                              >
                                📋
                              </button>
                              <button 
                                onClick={() => startEditPassword(p.id, p.website, p.password, p.username)}
                                className="bg-cyan-600 hover:bg-cyan-700 text-white px-2 py-1.5 rounded-lg transition text-xs"
                                title="Edit"
                              >
                                ✏️
                              </button>
                              <button 
                                onClick={() => deletePassword(p.id)}
                                className="bg-red-600 hover:bg-red-700 text-white px-2 py-1.5 rounded-lg transition text-xs"
                                title="Delete"
                              >
                                🗑️
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>

            {/* Right: Generator + Save/Edit */}
            <div className="w-full lg:w-[420px] space-y-6">
              <div className="panel-scroll bg-slate-800 border border-purple-500 rounded-lg p-6 shadow-2xl">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-2xl font-bold text-white">🎲 Generate Strong Password</h2>
                  <button 
                    onClick={() => setShowSettings(!showSettings)}
                    className="text-purple-300 hover:text-purple-100"
                  >
                    ⚙️ Settings
                  </button>
                </div>
                
                {showSettings ? (
                  <div className="panel-inner bg-slate-700 p-4 rounded-lg mb-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <label className="text-white">Length: {passwordLength}</label>
                      <input 
                        type="range" 
                        min="8" 
                        max="32" 
                        value={passwordLength}
                        onChange={(e) => setPasswordLength(parseInt(e.target.value))}
                        className="w-48" 
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <label className="flex items-center text-white cursor-pointer">
                        <input 
                          type="checkbox" 
                          checked={includeUppercase}
                          onChange={(e) => setIncludeUppercase(e.target.checked)}
                          className="mr-2" 
                        /> 
                        Uppercase (A-Z)
                      </label>
                      <label className="flex items-center text-white cursor-pointer">
                        <input 
                          type="checkbox" 
                          checked={includeLowercase}
                          onChange={(e) => setIncludeLowercase(e.target.checked)}
                          className="mr-2" 
                        /> 
                        Lowercase (a-z)
                      </label>
                      <label className="flex items-center text-white cursor-pointer">
                        <input 
                          type="checkbox" 
                          checked={includeNumbers}
                          onChange={(e) => setIncludeNumbers(e.target.checked)}
                          className="mr-2" 
                        /> 
                        Numbers (0-9)
                      </label>
                      <label className="flex items-center text-white cursor-pointer">
                        <input 
                          type="checkbox" 
                          checked={includeSymbols}
                          onChange={(e) => setIncludeSymbols(e.target.checked)}
                          className="mr-2" 
                        /> 
                        Symbols (!@#)
                      </label>
                    </div>
                  </div>
                ) : null}
                
                <button 
                  onClick={generatePassword}
                  className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-bold py-3 px-6 rounded-lg transition mb-3"
                >
                  🎲 Generate Password
                </button>
                
                {generatedPassword ? (
                  <div className="space-y-2">
                    {strength ? (
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-slate-700 rounded-full h-2">
                          <div 
                            className="h-2 rounded-full transition-all" 
                            style={{ 
                              width: strength.level === 'weak' ? '33%' : strength.level === 'medium' ? '66%' : '100%', 
                              backgroundColor: strength.color === 'red' ? '#ef4444' : strength.color === 'yellow' ? '#eab308' : '#22c55e' 
                            }}
                          ></div>
                        </div>
                        <span 
                          className="font-bold text-sm" 
                          style={{ color: strength.color === 'red' ? '#f87171' : strength.color === 'yellow' ? '#facc15' : '#4ade80' }}
                        >
                          {strength.text}
                        </span>
                      </div>
                    ) : null}
                    
                    <div className="flex gap-2">
                      <input 
                        type={showGeneratedPassword ? "text" : "password"} 
                        value={generatedPassword} 
                        readOnly 
                        className="mono-wrap flex-1 bg-slate-700 text-white p-3 rounded-lg border border-purple-500 font-mono" 
                      />
                      <button 
                        onClick={toggleGeneratedPasswordVisibility}
                        className="btn-hover bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg transition"
                        title={showGeneratedPassword ? "Hide" : "Show"}
                      >
                        {showGeneratedPassword ? '👁️' : '🔒'}
                      </button>
                      <button 
                        onClick={() => copyToClipboard(generatedPassword)}
                        className="btn-hover bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition"
                        title="Copy"
                      >
                        📋
                      </button>
                      <button 
                        onClick={useGeneratedPassword}
                        className="btn-hover bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded-lg transition"
                        title="Use"
                      >
                        ✅
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
              
              <div className="bg-slate-800 border border-purple-500 rounded-lg p-6 shadow-2xl">
                <h2 className="text-2xl font-bold text-white mb-4">
                  {editingPasswordId ? '✏️ Edit Password' : '💾 Save Password'}
                </h2>
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <input 
                      type="text" 
                      placeholder="Website (e.g., gmail.com)" 
                      value={newWebsite}
                      onChange={(e) => setNewWebsite(e.target.value)}
                      className="w-1/2 bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500" 
                    />
                    <input 
                      type="text" 
                      placeholder="Username (e.g., user123)" 
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      className="w-1/2 bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500" 
                    />
                  </div>
                  <input 
                    type="password" 
                    placeholder="Password" 
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-slate-700 text-white p-3 rounded-lg border border-purple-500 focus:outline-none focus:border-pink-500 font-mono" 
                  />
                  
                  {editingPasswordId ? (
                    <div className="flex gap-2">
                      <button 
                        onClick={updatePassword}
                        className="flex-1 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3 px-6 rounded-lg transition"
                      >
                        ✏️ Update Password
                      </button>
                      <button 
                        onClick={cancelEdit}
                        className="bg-slate-600 hover:bg-slate-500 text-white font-bold py-3 px-6 rounded-lg transition"
                      >
                        ❌ Cancel
                      </button>
                    </div>
                  ) : (
                    <button 
                      onClick={savePassword}
                      className="w-full bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg transition"
                    >
                      💾 Save Password
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Toast Notification */}
        {toastMessage && (
          <div 
            id="toast"
            className={`fixed top-4 right-4 px-6 py-3 rounded-lg shadow-2xl text-white font-bold z-50 transition-opacity duration-300 ${
              toastType === 'success' ? 'bg-gradient-to-r from-green-600 to-emerald-600' :
              toastType === 'error' ? 'bg-gradient-to-r from-red-600 to-pink-600' :
              'bg-gradient-to-r from-blue-600 to-purple-600'
            }`}
          >
            {toastMessage}
          </div>
        )}

        {/* Delete Confirmation Modal */}
        {showDeleteConfirm && (
          <div className="fixed inset-0 flex items-center justify-center z-50">
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm"></div>
            <div className="relative bg-[#0F1E2E] border border-[#F48120] rounded-xl p-6 w-[360px] shadow-2xl animate-slideIn">
              <h3 className="text-xl font-bold text-white mb-2">{deletePromptTitle}</h3>
              <p className="text-sm text-gray-300 mb-4">{deletePromptText}</p>
              <div className="flex gap-3">
                <button 
                  onClick={confirmDelete}
                  className="btn-hover flex-1 bg-gradient-to-r from-red-600 to-orange-600 text-white font-bold py-2 rounded-lg transition"
                >
                  Delete
                </button>
                <button 
                  onClick={cancelDelete}
                  className="btn-hover flex-1 bg-slate-600 text-white font-bold py-2 rounded-lg transition"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div>
      {screen === 'login' && renderLoginScreen()}
      {screen === 'register' && renderRegisterScreen()}
      {screen === 'app' && renderAppScreen()}
    </div>
  );
};