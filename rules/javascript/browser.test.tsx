import React from 'react';

export const Preview = ({ html }: { html: string }) => {
  const q = new URLSearchParams(window.location.search).get('q') ?? '';
  // ruleid: fortify.cross-site-scripting-dom
  const fromUrl = <div dangerouslySetInnerHTML={{ __html: q }} />;
  // ok: fortify.cross-site-scripting-dom
  const fromProp = <div dangerouslySetInnerHTML={{ __html: html }} />;
  // ruleid: fortify.privacy-violation-autocomplete
  const bare = <input type="password" name="pw" />;
  // ok: fortify.privacy-violation-autocomplete
  const managed = <input type="password" name="pw" autoComplete="current-password" />;
  return (
    <div>
      {fromUrl}
      {fromProp}
      {bare}
      {managed}
    </div>
  );
};
