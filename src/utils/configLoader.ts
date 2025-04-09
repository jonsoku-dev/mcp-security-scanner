import * as fs from 'fs';
import * as path from 'path';

export class ConfigLoader {
  loadConfig(configPath?: string): any {
    const defaultConfig = {
      suspiciousPatterns: [
        'file://', '~/.ssh', '~/.config', 'password', 'token', 'secret',
        '<IMPORTANT>', 'do not mention', 'do not tell the user'
      ],
      allowedPermissions: ['read', 'list', 'search']
    };

    if (!configPath) {
      return defaultConfig;
    }

    try {
      const configContent = fs.readFileSync(path.resolve(configPath), 'utf-8');
      const customConfig = JSON.parse(configContent);
      return {
        ...defaultConfig,
        ...customConfig
      };
    } catch (error) {
      console.warn(`Failed to load config from ${configPath}, using default config`);
      return defaultConfig;
    }
  }
}
