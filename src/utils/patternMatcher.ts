export interface PatternMatch {
  pattern: string;
  index: number;
  length: number;
}

export class PatternMatcher {
  private patterns: string[];

  constructor(patterns: string[]) {
    this.patterns = patterns;
  }

  findMatches(text: string): PatternMatch[] {
    const matches: PatternMatch[] = [];
    
    for (const pattern of this.patterns) {
      let index = text.toLowerCase().indexOf(pattern.toLowerCase());
      while (index !== -1) {
        matches.push({
          pattern,
          index,
          length: pattern.length
        });
        index = text.toLowerCase().indexOf(pattern.toLowerCase(), index + 1);
      }
    }

    return matches;
  }
}
