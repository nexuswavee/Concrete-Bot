#!/usr/bin/env node

require('dotenv').config();
const { ethers } = require("ethers");
const axios = require("axios");
const fs = require('fs');
const path = require('path');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const chalk = require('chalk');
const figlet = require('figlet');
const gradient = require('gradient-string');
const readline = require('readline');
const Table = require('cli-table3');

//
const CONFIG = {
  REF_CODE: "f83d5a9b",
  SEASON: "z2zi-tzc2",
  API_URL: "https://points.concrete.xyz/api",
  GQL_URL: "https://gql3.absinthe.network/v1/graphql",
  DELAY_BETWEEN_ACCOUNTS: 3000,
  CHECK_INTERVAL_HOURS: 24,
};

//
const sessions = new Map();

//
const LANGUAGES = {
  EN: {
    selectLanguage: "SELECT LANGUAGE",
    english: "English",
    russian: "Russian",
    loadingConfig: "Loading configuration",
    loadingAccounts: "Loading accounts",
    loadingProxies: "Loading proxies",
    accountsFound: "accounts found",
    proxiesFound: "proxies found",
    selectProxyMode: "SELECT PROXY MODE",
    withProxy: "With proxy",
    withoutProxy: "Without proxy",
    proxyRotation: "Enable proxy rotation on failure",
    yes: "Yes",
    no: "No",
    starting: "Starting automation",
    processing: "Processing",
    account: "Account",
    authentication: "Authentication",
    checkin: "Daily check-in",
    success: "Success",
    alreadyDone: "Already completed",
    failed: "Failed",
    waitingNext: "Waiting for next cycle",
    cycleComplete: "Cycle completed",
    nextCycle: "Next cycle in",
    statistics: "Statistics",
    total: "Total",
    successful: "Successful",
    errors: "Errors",
    alreadyChecked: "Already checked",
    time: "Time",
    pressKey: "Press key to select",
    invalidKey: "Invalid key, please try again",
    operationCompleted: "Operation completed",
    noKeysFound: "No private keys found in .env file",
    noProxiesFound: "No proxies found in proxies.txt",
    runningWithoutProxy: "Running without proxy",
    
    menuTitle: "RUN PARAMETERS",
    selectOption: "Select option",
    option1: "Run with proxy",
    option2: "Run without proxy",
    confirmRotation: "Enable automatic invalid proxy rotation",
    confirmYes: "Yes",
    confirmNo: "No"
  },
  RU: {
    selectLanguage: "ВЫБЕРИТЕ ЯЗЫК",
    english: "Английский",
    russian: "Русский",
    loadingConfig: "Загрузка конфигурации",
    loadingAccounts: "Загрузка аккаунтов",
    loadingProxies: "Загрузка прокси",
    accountsFound: "аккаунтов найдено",
    proxiesFound: "прокси найдено",
    selectProxyMode: "ВЫБЕРИТЕ РЕЖИМ ПРОКСИ",
    withProxy: "С прокси",
    withoutProxy: "Без прокси",
    proxyRotation: "Включить ротацию прокси при ошибке",
    yes: "Да",
    no: "Нет",
    starting: "Запуск автоматизации",
    processing: "Обработка",
    account: "Аккаунт",
    authentication: "Аутентификация",
    checkin: "Ежедневный чек-ин",
    success: "Успешно",
    alreadyDone: "Уже выполнено",
    failed: "Ошибка",
    waitingNext: "Ожидание следующего цикла",
    cycleComplete: "Цикл завершен",
    nextCycle: "Следующий цикл через",
    statistics: "Статистика",
    total: "Всего",
    successful: "Успешных",
    errors: "Ошибок",
    alreadyChecked: "Уже проверено",
    time: "Время",
    pressKey: "Нажмите клавишу для выбора",
    invalidKey: "Неверная клавиша, попробуйте снова",
    operationCompleted: "Операция завершена",
    noKeysFound: "Приватные ключи не найдены в файле .env",
    noProxiesFound: "Прокси не найдены в файле proxies.txt",
    runningWithoutProxy: "Запуск без прокси",
    
    menuTitle: "ПАРАМЕТРЫ ЗАПУСКА",
    selectOption: "Выберите опцию",
    option1: "Запуск с прокси",
    option2: "Запуск без прокси",
    confirmRotation: "Включить автоматическую ротацию недействительных прокси",
    confirmYes: "Да",
    confirmNo: "Нет"
  }
};

class ConcreteBot {
  constructor() {
    this.privateKeys = [];
    this.proxies = [];
    this.proxyIndex = 0;
    this.accountProxies = new Map();
    this.failedProxies = new Set();
    this.currentLanguage = LANGUAGES.EN;
    this.useProxy = false;
    this.rotateProxy = false;
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    this.stats = {
      totalAccounts: 0,
      successfulOperations: 0,
      failedOperations: 0,
      alreadyCheckedIn: 0,
      cycleStartTime: null,
      totalCycles: 0
    };
    
    //
    this.GREEN = chalk.hex('#00FF00');
    this.PINK = chalk.hex('#FF00FF');
    this.WHITE = chalk.white;
  }

  async initialize() {
    this.clearConsole();
    await this.displayBanner();
    await this.selectLanguage();
    await this.loadConfiguration();
    await this.configureRuntimeParameters();
    await this.executeAutomation();
  }

  clearConsole() {
    console.clear();
    process.stdout.write('\x1Bc');
  }

  async displayBanner() {
    const banner = figlet.textSync('CONCRETE', {
      font: 'ANSI Shadow',
      horizontalLayout: 'full'
    });

    console.log(gradient.pastel(banner));
    console.log('');
  }

  async selectLanguage() {
    console.log(this.PINK(this.currentLanguage.selectLanguage));
    console.log('');
    
    console.log(this.WHITE(' [1] ') + this.GREEN(LANGUAGES.EN.english));
    console.log(this.WHITE(' [2] ') + this.GREEN(LANGUAGES.RU.russian));
    console.log('');
    
    const choice = await this.promptForKey(['1', '2']);
    
    this.currentLanguage = choice === '1' ? LANGUAGES.EN : LANGUAGES.RU;
    
    console.log(this.GREEN(`✓ ${choice === '1' ? 'English' : 'Русский'} selected`));
    console.log('');
  }

  async promptForKey(validKeys) {
    return new Promise((resolve) => {
      const handler = (key) => {
        if (validKeys.includes(key.toLowerCase())) {
          this.rl.removeListener('keypress', handler);
          resolve(key.toLowerCase());
        } else {
          process.stdout.write(chalk.red(`\r${this.currentLanguage.invalidKey} `));
        }
      };
      
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on('keypress', handler);
      
      process.stdout.write(this.PINK(`${this.currentLanguage.pressKey}: `));
    });
  }

  async loadConfiguration() {
    console.log(this.PINK(this.currentLanguage.loadingConfig));
    
    this.privateKeys = this.loadPrivateKeys();
    if (this.privateKeys.length === 0) {
      console.log(chalk.red(`✗ ${this.currentLanguage.noKeysFound}`));
      process.exit(1);
    }
    
    this.proxies = this.loadProxies();
    
    console.log(this.GREEN(`✓ ${this.privateKeys.length} ${this.currentLanguage.accountsFound}`));
    if (this.proxies.length > 0) {
      console.log(this.GREEN(`✓ ${this.proxies.length} ${this.currentLanguage.proxiesFound}`));
    } else {
      console.log(chalk.yellow(`⚠ ${this.currentLanguage.noProxiesFound}`));
    }
    
    this.stats.totalAccounts = this.privateKeys.length;
    console.log('');
  }

  loadPrivateKeys() {
    try {
      const envPath = path.join(process.cwd(), '.env');
      if (!fs.existsSync(envPath)) return [];
      
      const content = fs.readFileSync(envPath, 'utf-8');
      return content
        .split('\n')
        .map(line => line.trim())
        .filter(line => {
          if (!line || line.startsWith('#') || line.startsWith('//')) return false;
          const key = line.startsWith('0x') ? line : '0x' + line;
          return key.length === 66;
        })
        .map(key => key.startsWith('0x') ? key : '0x' + key);
    } catch (error) {
      return [];
    }
  }

  loadProxies() {
    try {
      const proxyPath = path.join(process.cwd(), 'proxies.txt');
      if (!fs.existsSync(proxyPath)) return [];
      
      const content = fs.readFileSync(proxyPath, 'utf-8');
      return content
        .split('\n')
        .map(line => line.trim())
        .filter(line => {
          if (!line || line.startsWith('#')) return false;
          return line.startsWith('http://') || 
                 line.startsWith('https://') || 
                 line.startsWith('socks4://') || 
                 line.startsWith('socks5://') ||
                 /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(line);
        })
        .map(proxy => {
          if (!proxy.startsWith('http://') && 
              !proxy.startsWith('https://') && 
              !proxy.startsWith('socks')) {
            return `http://${proxy}`;
          }
          return proxy;
        });
    } catch (error) {
      return [];
    }
  }

  async configureRuntimeParameters() {
    console.log(this.PINK(this.currentLanguage.menuTitle));
    console.log('');
    
    console.log(this.WHITE(' [1] ') + this.GREEN(this.currentLanguage.option1));
    console.log(this.WHITE(' [2] ') + this.GREEN(this.currentLanguage.option2));
    console.log('');
    
    const proxyChoice = await this.promptForKey(['1', '2']);
    this.useProxy = proxyChoice === '1';
    
    if (!this.useProxy || this.proxies.length === 0) {
      this.useProxy = false;
      console.log(chalk.yellow(`⚠ ${this.currentLanguage.runningWithoutProxy}`));
      console.log('');
      return;
    }
    
    console.log(this.PINK(this.currentLanguage.confirmRotation));
    console.log(this.WHITE('\n [Y] ') + this.GREEN(this.currentLanguage.confirmYes));
    console.log(this.WHITE(' [N] ') + this.GREEN(this.currentLanguage.confirmNo));
    console.log('');
    
    const rotationChoice = await this.promptForKey(['y', 'n']);
    this.rotateProxy = rotationChoice === 'y';
    
    console.log(this.GREEN(`✓ ${this.currentLanguage.operationCompleted}`));
    console.log('');
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  formatAddress(address) {
    return address.substring(0, 8) + '...' + address.substring(address.length - 6);
  }

  formatTime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }

  getProxyForAccount(account) {
    if (!this.useProxy || this.proxies.length === 0) return null;
    
    if (!this.accountProxies.has(account)) {
      let proxy;
      let attempts = 0;
      
      do {
        proxy = this.proxies[this.proxyIndex % this.proxies.length];
        this.proxyIndex++;
        attempts++;
        
        if (attempts > this.proxies.length * 2) {
          return null;
        }
      } while (this.failedProxies.has(proxy));
      
      this.accountProxies.set(account, proxy);
    }
    
    return this.accountProxies.get(account);
  }

  markProxyAsFailed(proxy) {
    if (proxy && this.rotateProxy) {
      this.failedProxies.add(proxy);
      this.accountProxies.clear();
    }
  }

  createAgent(proxy) {
    if (!proxy) return null;
    
    try {
      if (proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) {
        return new SocksProxyAgent(proxy);
      } else {
        return new HttpsProxyAgent(proxy);
      }
    } catch (error) {
      this.markProxyAsFailed(proxy);
      return null;
    }
  }

  async checkSessionValid(session, walletAddress) {
    try {
      if (!session || !session.token || !session.cookies) {
        return false;
      }
      
      if (session.lastAuth && (Date.now() - session.lastAuth) > 24 * 60 * 60 * 1000) {
        return false;
      }
      
      const config = this.createAxiosConfig(session.proxy);
      config.headers['Cookie'] = session.cookies;
      
      const response = await axios.get(`${CONFIG.API_URL}/auth/session`, config);
      
      return response.data && response.data.user && response.data.token;
      
    } catch (error) {
      return false;
    }
  }

  createAxiosConfig(proxy) {
    const config = {
      timeout: 30000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
      }
    };

    if (proxy) {
      const agent = this.createAgent(proxy);
      if (agent) {
        config.httpsAgent = agent;
        config.httpAgent = agent;
      }
    }

    return config;
  }

  extractCookiesFromHeaders(headers) {
    const cookies = headers['set-cookie'] || [];
    let cookieString = '';
    
    cookies.forEach(cookie => {
      const cookiePart = cookie.split(';')[0];
      if (cookiePart.includes('=')) {
        cookieString += cookiePart + '; ';
      }
    });
    
    return cookieString.trim();
  }

  normalizePrivateKey(key) {
    let normalized = key.trim();
    normalized = normalized.replace(/['"]/g, '');
    if (!normalized.startsWith('0x')) {
      normalized = '0x' + normalized;
    }
    return normalized;
  }

  async getCsrfTokenWithCookies(proxy) {
    try {
      const initialCookies = `client-season=${CONFIG.SEASON}; domain=https%3A%2F%2Fpoints.concrete.xyz; __Secure-authjs.callback-url=https%3A%2F%2Fboost.absinthe.network; redirect-pathname=%2Fhome`;
      
      const config = this.createAxiosConfig(proxy);
      config.headers['Cookie'] = initialCookies;
      
      const response = await axios.get(`${CONFIG.API_URL}/auth/csrf`, config);
      
      const csrfToken = response.data.csrfToken;
      const newCookies = this.extractCookiesFromHeaders(response.headers);
      
      const combinedCookies = initialCookies + (newCookies ? '; ' + newCookies : '');
      
      return { csrfToken, cookies: combinedCookies };
      
    } catch (error) {
      this.markProxyAsFailed(proxy);
      throw new Error('CSRF_ERROR');
    }
  }

  async createSignature(wallet, csrfToken) {
    const message = `points.concrete.xyz wants you to sign in with your Ethereum account:\n${wallet.address}\n\nPlease sign with your account\n\nURI: https://points.concrete.xyz\nVersion: 1\nChain ID: 1\nNonce: ${csrfToken}\nIssued At: ${new Date().toISOString()}\nResources:\n- connector://metaMask`;
    const signature = await wallet.signMessage(message);
    return { message, signature };
  }

  async authenticateUser(message, signature, csrfToken, cookies, proxy) {
    try {
      const config = this.createAxiosConfig(proxy);
      config.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      config.headers['Cookie'] = cookies;
      config.headers['Origin'] = 'https://points.concrete.xyz';
      config.headers['Referer'] = 'https://points.concrete.xyz/home';
      config.maxRedirects = 0;
      
      const response = await axios.post(
        `${CONFIG.API_URL}/auth/callback/credentials`,
        new URLSearchParams({
          message,
          signature,
          csrfToken,
          callbackUrl: "https://points.concrete.xyz/home",
          redirect: "false"
        }),
        config
      );
      
      const newCookies = this.extractCookiesFromHeaders(response.headers);
      const updatedCookies = cookies + (newCookies ? '; ' + newCookies : '');
      
      return updatedCookies;
      
    } catch (error) {
      if (error.response && error.response.status === 302) {
        const newCookies = this.extractCookiesFromHeaders(error.response.headers);
        const updatedCookies = cookies + (newCookies ? '; ' + newCookies : '');
        return updatedCookies;
      }
      
      this.markProxyAsFailed(proxy);
      throw new Error('AUTH_ERROR');
    }
  }

  async getSessionWithCookies(cookies, proxy) {
    try {
      const config = this.createAxiosConfig(proxy);
      config.headers['Cookie'] = cookies;
      config.headers['Accept'] = 'application/json';
      config.headers['Referer'] = 'https://points.concrete.xyz/home';
      
      const response = await axios.get(`${CONFIG.API_URL}/auth/session`, config);
      
      if (!response.data) {
        throw new Error('INVALID_SESSION');
      }
      
      const token = response.data.token;
      const userId = response.data.user?.id;
      
      if (!token || !userId) {
        throw new Error('INVALID_SESSION_DATA');
      }
      
      return { token, userId, cookies };
    } catch (error) {
      this.markProxyAsFailed(proxy);
      throw new Error('SESSION_ERROR');
    }
  }

  async authenticateWithSession(wallet, proxy) {
    const walletAddress = wallet.address.toLowerCase();
    
    if (sessions.has(walletAddress)) {
      const session = sessions.get(walletAddress);
      
      if (await this.checkSessionValid(session, walletAddress)) {
        return session;
      } else {
        sessions.delete(walletAddress);
      }
    }
    
    try {
      const { csrfToken, cookies: csrfCookies } = await this.getCsrfTokenWithCookies(proxy);
      
      const { message, signature } = await this.createSignature(wallet, csrfToken);

      const authCookies = await this.authenticateUser(message, signature, csrfToken, csrfCookies, proxy);

      const { token, userId, cookies } = await this.getSessionWithCookies(authCookies, proxy);

      const newSession = {
        token,
        userId,
        cookies,
        proxy,
        lastAuth: Date.now(),
        walletAddress
      };
      
      sessions.set(walletAddress, newSession);
      
      return newSession;
      
    } catch (error) {
      this.markProxyAsFailed(proxy);
      throw error;
    }
  }

  async applyReferralCode(session) {
    try {
      const config = this.createAxiosConfig(session.proxy);
      config.headers['Authorization'] = `Bearer ${session.token}`;
      config.headers['Content-Type'] = 'application/json';
      
      await axios.post(
        CONFIG.GQL_URL,
        {
          query: `mutation {
            apply_referral_code(referral_code_data: {
              referral_code: "${CONFIG.REF_CODE}",
              user_id: "${session.userId}"
            }) { success }
          }`
        },
        config
      );
      
      return true;
    } catch (error) {
      return false;
    }
  }

  async getAccountInfo(session) {
    try {
      const config = this.createAxiosConfig(session.proxy);
      config.headers['Authorization'] = `Bearer ${session.token}`;
      config.headers['Content-Type'] = 'application/json';
      
      const response = await axios.post(
        CONFIG.GQL_URL,
        {
          query: `query {
            get_leaderboard_v2(get_leaderboard_v2_data: {
              client_season: "${CONFIG.SEASON}",
              user_id: "${session.userId}"
            }) {
              leaderboard {
                points_rank
                gold_score
                xp_score
                gems_score
              }
            }
          }`
        },
        config
      );
      
      return response.data?.data?.get_leaderboard_v2?.leaderboard?.[0] || null;
    } catch {
      return null;
    }
  }

  async performDailyCheckin(session) {
    try {
      const config = this.createAxiosConfig(session.proxy);
      config.headers['Authorization'] = `Bearer ${session.token}`;
      config.headers['Content-Type'] = 'application/json';
      
      const sourceResponse = await axios.post(
        CONFIG.GQL_URL,
        {
          query: `query {
            points_config_point_sources(where: {
              client_season: {_eq: "${CONFIG.SEASON}"},
              source_type: {_eq: daily_checkin}
            }) { id }
          }`
        },
        config
      );
      
      const sourceId = sourceResponse.data?.data?.points_config_point_sources[0]?.id;
      if (!sourceId) throw new Error('NO_SOURCE');
      
      const checkinResponse = await axios.post(
        CONFIG.GQL_URL,
        {
          query: `mutation {
            daily_checkin(point_source_data: {
              user_id: "${session.userId}",
              client_season: "${CONFIG.SEASON}",
              point_source_id: "${sourceId}",
              status: "SUCCESS"
            }) { id }
          }`
        },
        config
      );
      
      if (checkinResponse.data?.errors) {
        const errorMsg = checkinResponse.data.errors[0]?.message;
        if (errorMsg?.includes('already checked in')) {
          return 'ALREADY_CHECKED';
        }
        throw new Error('CHECKIN_ERROR');
      }
      
      return 'SUCCESS';
    } catch (error) {
      this.markProxyAsFailed(session.proxy);
      return 'ERROR';
    }
  }

  createProgressTable() {
    return new Table({
      head: [
        this.PINK('#'),
        this.PINK(this.currentLanguage.account),
        this.PINK(this.currentLanguage.authentication),
        this.PINK(this.currentLanguage.checkin),
        this.PINK('Status')
      ],
      colWidths: [4, 22, 18, 18, 15],
      style: {
        head: [],
        border: []
      }
    });
  }

  updateProgressTable(table, index, address, authStatus, checkinStatus, status) {
    const row = [
      this.WHITE(index.toString().padStart(2)),
      this.GREEN(address),
      this.getStatusIcon(authStatus),
      this.getStatusIcon(checkinStatus),
      this.getStatusText(status)
    ];
    
    if (table.length > index - 1) {
      table[index - 1] = row;
    } else {
      table.push(row);
    }
    
    this.clearConsole();
    this.displayBanner();
    console.log(this.PINK(this.currentLanguage.processing.toUpperCase()));
    console.log('');
    console.log(table.toString());
  }

  getStatusIcon(status) {
    switch(status) {
      case 'PENDING': return chalk.yellow('⌛');
      case 'SUCCESS': return this.GREEN('✓');
      case 'ERROR': return chalk.red('✗');
      default: return this.WHITE('─');
    }
  }

  getStatusText(status) {
    switch(status) {
      case 'SUCCESS': return this.GREEN(this.currentLanguage.success);
      case 'ALREADY_CHECKED': return chalk.yellow(this.currentLanguage.alreadyDone);
      case 'ERROR': return chalk.red(this.currentLanguage.failed);
      case 'PROCESSING': return this.PINK('Processing');
      default: return this.WHITE('Waiting');
    }
  }

  async processAccount(privateKey, index) {
    const normalizedKey = this.normalizePrivateKey(privateKey);
    const wallet = new ethers.Wallet(normalizedKey);
    const address = this.formatAddress(wallet.address);
    const proxy = this.getProxyForAccount(address);
    
    const table = this.createProgressTable();
    let authStatus = 'PENDING';
    let checkinStatus = 'PENDING';
    let finalStatus = 'PROCESSING';
    
    try {
      this.updateProgressTable(table, index, address, authStatus, checkinStatus, finalStatus);
      
      const session = await this.authenticateWithSession(wallet, proxy);
      authStatus = 'SUCCESS';
      this.updateProgressTable(table, index, address, authStatus, checkinStatus, finalStatus);
      
      await this.applyReferralCode(session);
      
      await this.getAccountInfo(session);
      
      const checkinResult = await this.performDailyCheckin(session);
      
      checkinStatus = checkinResult === 'ERROR' ? 'ERROR' : 'SUCCESS';
      finalStatus = checkinResult;
      
      if (checkinResult === 'SUCCESS') {
        this.stats.successfulOperations++;
      } else if (checkinResult === 'ALREADY_CHECKED') {
        this.stats.alreadyCheckedIn++;
      } else {
        this.stats.failedOperations++;
      }
      
    } catch (error) {
      authStatus = 'ERROR';
      checkinStatus = 'ERROR';
      finalStatus = 'ERROR';
      this.stats.failedOperations++;
      this.markProxyAsFailed(proxy);
    }
    
    this.updateProgressTable(table, index, address, authStatus, checkinStatus, finalStatus);
    
    await this.sleep(CONFIG.DELAY_BETWEEN_ACCOUNTS);
  }

  displayStatistics() {
    console.log('');
    console.log(this.PINK(this.currentLanguage.statistics.toUpperCase()));
    console.log('');
    
    const statsTable = new Table({
      style: { border: [] }
    });
    
    statsTable.push(
      [this.GREEN(this.currentLanguage.total), this.WHITE(this.stats.totalAccounts.toString())],
      [this.GREEN(this.currentLanguage.successful), this.GREEN(this.stats.successfulOperations.toString())],
      [this.GREEN(this.currentLanguage.alreadyChecked), chalk.yellow(this.stats.alreadyCheckedIn.toString())],
      [this.GREEN(this.currentLanguage.errors), chalk.red(this.stats.failedOperations.toString())]
    );
    
    console.log(statsTable.toString());
    console.log('');
    
    const successRate = this.stats.totalAccounts > 0 
      ? ((this.stats.successfulOperations + this.stats.alreadyCheckedIn) / this.stats.totalAccounts * 100).toFixed(1)
      : 0;
    
    console.log(this.GREEN(`${this.currentLanguage.success}: ${successRate}%`));
    console.log('');
  }

  async executeAutomation() {
    this.stats.cycleStartTime = Date.now();
    this.stats.totalCycles++;
    
    console.log(this.PINK(this.currentLanguage.starting.toUpperCase()));
    console.log('');
    
    console.log(this.WHITE(`Accounts: ${this.stats.totalAccounts}`));
    if (this.useProxy && this.proxies.length > 0) {
      console.log(this.WHITE(`Proxies: ${this.proxies.length}`));
      if (this.rotateProxy) {
        console.log(this.WHITE(`Proxy rotation: Enabled`));
      }
    }
    console.log('');
    
    for (let i = 0; i < this.privateKeys.length; i++) {
      await this.processAccount(this.privateKeys[i], i + 1);
    }
    
    this.displayStatistics();
    
    await this.waitForNextCycle();
  }

  async waitForNextCycle() {
    console.log(this.PINK(this.currentLanguage.cycleComplete.toUpperCase()));
    console.log('');
    
    const waitTime = CONFIG.CHECK_INTERVAL_HOURS * 3600;
    
    for (let i = waitTime; i > 0; i--) {
      const hours = Math.floor(i / 3600);
      const minutes = Math.floor((i % 3600) / 60);
      const seconds = i % 60;
      
      process.stdout.write(
        this.GREEN(`\r${this.currentLanguage.nextCycle}: `) +
        this.GREEN(
          `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
        ) +
        this.WHITE(` | Cycle: ${this.stats.totalCycles}`)
      );
      
      await this.sleep(1000);
    }
    
    console.log(this.GREEN('\n\nStarting new cycle...\n'));
    await this.sleep(2000);
    
    this.stats.successfulOperations = 0;
    this.stats.failedOperations = 0;
    this.stats.alreadyCheckedIn = 0;
    this.stats.cycleStartTime = Date.now();
    
    await this.executeAutomation();
  }

  async run() {
    try {
      await this.initialize();
    } catch (error) {
      console.error(chalk.red('\n✗ Fatal error:'), error.message);
      process.exit(1);
    }
  }
}

const bot = new ConcreteBot();
bot.run();

process.on('SIGINT', () => {
  console.log(chalk.yellow('\n\nProcess interrupted by user'));
  process.exit(0);
});

process.on('unhandledRejection', (error) => {
  console.error(chalk.red('\n✗ Unhandled rejection:'), error);
});
