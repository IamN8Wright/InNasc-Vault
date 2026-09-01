import fontkit from '@pdf-lib/fontkit';
import fs from 'node:fs/promises';
import path from 'node:path';
import { PDFDocument, type PDFFont, type PDFPage, rgb } from 'pdf-lib';

export type OffboardingSecret = {
  username: string;
  password: string;
  pin: string;
  apiToken: string;
  licenseKey: string;
  notes: string;
};

export type OffboardingCredential = {
  name: string;
  collection: string;
  systemName: string;
  url: string;
  lastVerifiedAt: string;
  expiresAt: string;
  secret: OffboardingSecret;
};

export type OffboardingLocation = {
  name: string;
  address: string;
  notes: string;
  systems: Array<Record<string, unknown>>;
  assets: Array<Record<string, unknown>>;
  credentials: OffboardingCredential[];
};

export type OffboardingClient = {
  name: string;
  code: string;
  notes: string;
  locations: OffboardingLocation[];
};

export function textValue(value: unknown) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  return JSON.stringify(value) ?? '';
}

function readableLabel(value: unknown) {
  return textValue(value).replaceAll('_', ' ').replace(/\b\w/gu, (character) => character.toUpperCase());
}

const pageWidth = 612;
const pageHeight = 792;
const margin = 42;
const contentWidth = pageWidth - margin * 2;
const footerY = 25;
const contentBottom = 46;

const colors = {
  navy: rgb(15 / 255, 35 / 255, 58 / 255),
  blue: rgb(31 / 255, 93 / 255, 217 / 255),
  bluePale: rgb(232 / 255, 240 / 255, 1),
  gray: rgb(82 / 255, 99 / 255, 119 / 255),
  line: rgb(209 / 255, 219 / 255, 230 / 255),
  panel: rgb(246 / 255, 248 / 255, 251 / 255),
  red: rgb(180 / 255, 35 / 255, 24 / 255),
  redPale: rgb(1, 241 / 255, 240 / 255),
  amber: rgb(138 / 255, 75 / 255, 8 / 255),
  amberPale: rgb(1, 248 / 255, 232 / 255),
  white: rgb(1, 1, 1),
};

function safeForFont(value: unknown, supported: Set<number>) {
  const normalized = textValue(value).replaceAll('\t', '    ').replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  return Array.from(normalized).map((character) => {
    const codePoint = character.codePointAt(0)!;
    if (character === '\n' || supported.has(codePoint)) return character;
    return `[U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}]`;
  }).join('');
}

function wrapText(value: string, font: PDFFont, size: number, width: number) {
  const lines: string[] = [];
  for (const paragraph of value.split('\n')) {
    if (!paragraph) {
      lines.push('');
      continue;
    }
    let line = '';
    let lineWidth = 0;
    for (const character of Array.from(paragraph)) {
      const characterWidth = font.widthOfTextAtSize(character, size);
      if (line && lineWidth + characterWidth > width) {
        lines.push(line);
        line = character;
        lineWidth = characterWidth;
      } else {
        line += character;
        lineWidth += characterWidth;
      }
    }
    lines.push(line);
  }
  return lines;
}

function wrapWords(value: string, font: PDFFont, size: number, width: number) {
  const lines: string[] = [];
  for (const paragraph of value.split('\n')) {
    if (!paragraph) {
      lines.push('');
      continue;
    }
    let line = '';
    for (const token of paragraph.split(/(\s+)/u).filter(Boolean)) {
      const candidate = `${line}${token}`;
      if (!line || font.widthOfTextAtSize(candidate, size) <= width) {
        line = candidate;
        continue;
      }
      lines.push(line.trimEnd());
      if (/^\s+$/u.test(token)) {
        line = '';
      } else if (font.widthOfTextAtSize(token, size) <= width) {
        line = token;
      } else {
        const pieces = wrapText(token, font, size, width);
        lines.push(...pieces.slice(0, -1));
        line = pieces.at(-1) ?? '';
      }
    }
    lines.push(line.trimEnd());
  }
  return lines;
}

function fittedSize(value: string, font: PDFFont, maximum: number, width: number, minimum = 7) {
  let size = maximum;
  while (size > minimum && font.widthOfTextAtSize(value, size) > width) size -= 0.5;
  return size;
}

export async function createOffboardingPdf(input: { exportedAt: string; exportedBy: string; clients: OffboardingClient[] }) {
  const assetRoot = process.cwd();
  const [regularBytes, boldBytes, logoBytes] = await Promise.all([
    fs.readFile(path.join(assetRoot, 'node_modules', 'notosans-fontface', 'fonts', 'NotoSans-Regular.ttf')),
    fs.readFile(path.join(assetRoot, 'node_modules', 'notosans-fontface', 'fonts', 'NotoSans-Bold.ttf')),
    fs.readFile(path.join(assetRoot, 'public', 'innasc-vault-mark.png')),
  ]);
  const document = await PDFDocument.create();
  document.registerFontkit(fontkit);
  const [regular, bold, logo] = await Promise.all([
    document.embedFont(regularBytes, { subset: true }),
    document.embedFont(boldBytes, { subset: true }),
    document.embedPng(logoBytes),
  ]);
  const supported = new Set(regular.getCharacterSet());
  const safe = (value: unknown) => safeForFont(value, supported);
  const pages: PDFPage[] = [];
  let page!: PDFPage;
  let y!: number;

  document.setTitle('InNasc Vault Offboarding Export');
  document.setAuthor('InNasc Vault');
  document.setCreator('InNasc Vault');
  document.setProducer('InNasc Vault');
  document.setSubject('Confidential plaintext credential offboarding document');
  document.setKeywords(['InNasc Vault', 'offboarding', 'confidential', 'credentials']);
  document.setCreationDate(new Date(input.exportedAt));
  document.setModificationDate(new Date(input.exportedAt));

  function newPage() {
    page = document.addPage([pageWidth, pageHeight]);
    pages.push(page);
    page.drawImage(logo, { x: margin, y: pageHeight - 58, width: 30, height: 30 });
    page.drawText('InNasc Vault', { x: margin + 39, y: pageHeight - 43, size: 12, font: bold, color: colors.navy });
    page.drawText('OFFBOARDING EXPORT', { x: margin + 39, y: pageHeight - 55, size: 7, font: bold, color: colors.blue });
    page.drawText('CONFIDENTIAL - PLAINTEXT CREDENTIALS', { x: pageWidth - margin - 190, y: pageHeight - 47, size: 7, font: bold, color: colors.red });
    page.drawLine({ start: { x: margin, y: pageHeight - 67 }, end: { x: pageWidth - margin, y: pageHeight - 67 }, thickness: 1, color: colors.line });
    y = pageHeight - 83;
  }

  function ensureSpace(height: number) {
    if (y - height < contentBottom) newPage();
  }

  function drawWrapped(value: unknown, options: { x?: number; width?: number; size?: number; font?: PDFFont; color?: ReturnType<typeof rgb>; lineHeight?: number; gapAfter?: number } = {}) {
    const x = options.x ?? margin;
    const width = options.width ?? contentWidth;
    const size = options.size ?? 9;
    const selectedFont = options.font ?? regular;
    const color = options.color ?? colors.navy;
    const lineHeight = options.lineHeight ?? size * 1.35;
    const lines = wrapWords(safe(value), selectedFont, size, width);
    for (const line of lines) {
      ensureSpace(lineHeight);
      if (line) page.drawText(line, { x, y, size, font: selectedFont, color });
      y -= lineHeight;
    }
    y -= options.gapAfter ?? 0;
  }

  function drawField(label: string, value: unknown, secret = false) {
    const normalized = textValue(value);
    if (!normalized) return;
    const labelWidth = 112;
    const valueWidth = contentWidth - labelWidth - 16;
    const fontSize = 8.2;
    const lineHeight = 11;
    const lines = wrapText(safe(normalized), regular, fontSize, valueWidth);
    lines.forEach((line, index) => {
      ensureSpace(15);
      if (secret) page.drawRectangle({ x: margin, y: y - 4, width: contentWidth, height: 15, color: colors.amberPale });
      if (index === 0) page.drawText(safe(label), { x: margin + 5, y, size: 7.6, font: bold, color: secret ? colors.amber : colors.gray });
      if (line) page.drawText(line, { x: margin + labelWidth, y, size: fontSize, font: regular, color: colors.navy });
      y -= lineHeight;
    });
    y -= 2;
  }

  function drawSection(title: string) {
    ensureSpace(27);
    y -= 5;
    page.drawText(safe(title.toUpperCase()), { x: margin, y, size: 8, font: bold, color: colors.blue });
    y -= 7;
    page.drawLine({ start: { x: margin, y }, end: { x: pageWidth - margin, y }, thickness: 0.8, color: colors.line });
    y -= 13;
  }

  function drawRecordTitle(title: unknown, followingHeight = 55) {
    ensureSpace(27 + followingHeight);
    page.drawRectangle({ x: margin, y: y - 5, width: contentWidth, height: 22, color: colors.panel, borderColor: colors.line, borderWidth: 0.6 });
    const value = safe(title);
    const size = fittedSize(value, bold, 10, contentWidth - 18);
    page.drawText(value, { x: margin + 8, y: y + 1, size, font: bold, color: colors.navy });
    y -= 28;
  }

  newPage();
  ensureSpace(112);
  const warningBottom = y - 101;
  page.drawRectangle({ x: margin, y: y - 101, width: contentWidth, height: 106, color: colors.redPale, borderColor: colors.red, borderWidth: 2 });
  page.drawText('CONFIDENTIAL - CONTAINS PLAINTEXT CREDENTIALS', { x: margin + 14, y: y - 18, size: 13, font: bold, color: colors.red });
  y -= 38;
  drawWrapped('This PDF is not encrypted. Store it on an encrypted drive or import it into a trusted password manager immediately.', { x: margin + 14, width: contentWidth - 28, size: 9, color: colors.navy, lineHeight: 12 });
  drawWrapped('Do not email it, upload it to ordinary cloud storage, or leave it in Downloads. Securely delete every copy when it is no longer needed.', { x: margin + 14, width: contentWidth - 28, size: 9, color: colors.navy, lineHeight: 12 });
  y = warningBottom - 17;
  drawField('Exported', input.exportedAt);
  drawField('Exported by', input.exportedBy);
  drawField('Source', 'InNasc Vault');
  y -= 8;

  for (const [clientIndex, client] of input.clients.entries()) {
    if (clientIndex > 0) newPage();
    ensureSpace(50);
    page.drawRectangle({ x: margin, y: y - 31, width: contentWidth, height: 38, color: colors.blue });
    page.drawText('CLIENT', { x: margin + 12, y: y - 3, size: 7, font: bold, color: colors.bluePale });
    const clientName = safe(client.name);
    const clientSize = fittedSize(clientName, bold, 17, contentWidth - (client.code ? 130 : 28), 10);
    page.drawText(clientName, { x: margin + 12, y: y - 23, size: clientSize, font: bold, color: colors.white });
    if (client.code) {
      const code = safe(client.code);
      const codeSize = fittedSize(code, bold, 9, 90, 6);
      page.drawText(code, { x: pageWidth - margin - bold.widthOfTextAtSize(code, codeSize) - 12, y: y - 18, size: codeSize, font: bold, color: colors.white });
    }
    y -= 44;
    if (client.notes) drawWrapped(client.notes, { size: 8.5, color: colors.gray, lineHeight: 11, gapAfter: 7 });

    for (const location of client.locations) {
      ensureSpace(38);
      const locationName = safe(location.name);
      page.drawText(locationName, { x: margin, y, size: fittedSize(locationName, bold, 14, contentWidth, 9), font: bold, color: colors.navy });
      y -= 17;
      if (location.address) drawWrapped(location.address, { size: 8.3, color: colors.gray, lineHeight: 10.5, gapAfter: 3 });
      if (location.notes) drawWrapped(location.notes, { size: 8.3, color: colors.gray, lineHeight: 10.5, gapAfter: 3 });

      if (location.systems.length) {
        drawSection('Systems');
        for (const system of location.systems) {
          drawRecordTitle(system.name, 80);
          drawField('Collection', readableLabel(system.collection));
          drawField('Manufacturer', system.manufacturer);
          drawField('Model', system.model);
          drawField('Network address', system.network_address);
          drawField('Notes', system.notes);
          y -= 12;
        }
      }

      if (location.assets.length) {
        drawSection('Devices, software & website accounts');
        for (const asset of location.assets) {
          drawRecordTitle(asset.name, 105);
          drawField('Type', readableLabel(asset.asset_type));
          drawField('System', asset.system_name);
          drawField('Vendor', asset.vendor);
          drawField('Version / model', asset.version_or_model);
          drawField('Identifier', asset.identifier);
          drawField('URL', asset.url);
          drawField('Notes', asset.notes);
          y -= 12;
        }
      }

      if (location.credentials.length) {
        drawSection('Usernames & passwords');
        for (const credential of location.credentials) {
          drawRecordTitle(credential.name, 128);
          drawField('Collection', readableLabel(credential.collection));
          drawField('System', credential.systemName);
          drawField('URL', credential.url);
          drawField('Username', credential.secret.username, true);
          drawField('Password', credential.secret.password, true);
          drawField('PIN', credential.secret.pin, true);
          drawField('API token', credential.secret.apiToken, true);
          drawField('License key', credential.secret.licenseKey, true);
          drawField('Secret notes', credential.secret.notes, true);
          drawField('Last verified', credential.lastVerifiedAt);
          drawField('Expires', credential.expiresAt);
          y -= 12;
        }
      }
      y -= 10;
    }
  }

  pages.forEach((item, index) => {
    item.drawLine({ start: { x: margin, y: footerY + 12 }, end: { x: pageWidth - margin, y: footerY + 12 }, thickness: 0.6, color: colors.line });
    item.drawText('InNasc Vault - Confidential plaintext export', { x: margin, y: footerY, size: 7, font: regular, color: colors.gray });
    const pageLabel = `Page ${index + 1} of ${pages.length}`;
    item.drawText(pageLabel, { x: pageWidth - margin - regular.widthOfTextAtSize(pageLabel, 7), y: footerY, size: 7, font: regular, color: colors.gray });
  });

  return document.save();
}
