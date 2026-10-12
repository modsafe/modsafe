import http from './client';
import { t } from '../i18n';

/** 合规报表 CSV 导出（P1-a）：带 JWT 拉取二进制并触发浏览器下载（CSV 已含 UTF-8 BOM，Excel 直开不乱码） */
export async function exportCsv(path: string, filename: string) {
  const resp = await http.get<Blob>(path, { responseType: 'blob' });
  const url = URL.createObjectURL(
    resp instanceof Blob ? resp : new Blob([resp as unknown as string], { type: 'text/csv' }),
  );
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export const csvButton = {
  text: t('导出 CSV'),
  onClick: () => exportCsv,
};
