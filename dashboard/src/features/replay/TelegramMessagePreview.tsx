import { createElement, type ReactNode } from 'react';

type TelegramTag = 'b' | 'i' | 'code';

function isOpeningTag(token: string): token is `<${TelegramTag}>` {
  return /^<(b|i|code)>$/.test(token);
}

function isClosingTag(token: string, activeTag: TelegramTag | null): boolean {
  return activeTag !== null && token === `</${activeTag}>`;
}

/** Hanya merender subset HTML kecil yang didukung Telegram untuk payload ini. */
export function TelegramMessagePreview({ message }: { message: string }) {
  const nodes: ReactNode[] = [];
  let activeTag: TelegramTag | null = null;
  let key = 0;

  for (const token of message.split(/(<\/?(?:b|i|code)>)/g)) {
    if (!token) continue;

    if (isOpeningTag(token)) {
      activeTag = token.slice(1, -1) as TelegramTag;
      continue;
    }
    if (isClosingTag(token, activeTag)) {
      activeTag = null;
      continue;
    }

    nodes.push(activeTag ? createElement(activeTag, { key: key++ }, token) : <span key={key++}>{token}</span>);
  }

  return <div className="whitespace-pre-wrap break-words text-sm leading-7 text-kumo-default">{nodes}</div>;
}
