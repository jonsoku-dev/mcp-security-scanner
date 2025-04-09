export class Logger {
  private level: string;

  constructor(level: string = 'info') {
    this.level = level;
  }

  info(message: string) {
    console.log(`[INFO] ${message}`);
  }

  warn(message: string) {
    console.warn(`[WARN] ${message}`);
  }

  error(message: string) {
    console.error(`[ERROR] ${message}`);
  }

  debug(message: string) {
    if (this.level === 'debug') {
      console.debug(`[DEBUG] ${message}`);
    }
  }
}
