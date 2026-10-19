import { TestBed } from '@angular/core/testing';
import { ClaimsTable } from './claims-table';

describe('ClaimsTable', () => {
  it('shows a claim value as text, never as markup', async () => {
    const fixture = TestBed.createComponent(ClaimsTable);
    fixture.componentRef.setInput('caption', 'Claims');
    fixture.componentRef.setInput('claims', { name: '<img src=x onerror=alert(1)>', exp: 1 });
    await fixture.whenStable();

    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('img')).toBeNull();
    expect(root.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('adds the notes column only when notes are given', async () => {
    const fixture = TestBed.createComponent(ClaimsTable);
    fixture.componentRef.setInput('caption', 'Claims');
    fixture.componentRef.setInput('claims', { email: 'a@b' });
    fixture.componentRef.setInput('notes', { email: 'email' });
    fixture.componentRef.setInput('notesHeading', 'Released by scope');
    await fixture.whenStable();

    const headers = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('thead th'));
    expect(headers.map((h) => h.textContent?.trim())).toEqual([
      'Claim',
      'Value',
      'Released by scope',
    ]);
  });
});
