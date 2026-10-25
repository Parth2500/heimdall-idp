import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { HdCard } from './card';

@Component({
  imports: [HdCard],
  template: `
    <hd-card host="acme.localhost:7299" state="busy" hostLabel="You are signed in at">
      <h1 hdStatement>Title</h1>
      <p class="task">Task</p>
    </hd-card>
  `,
})
class Host {}

describe('HdCard', () => {
  async function render(): Promise<HTMLElement> {
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  it('names the host and tells the user to compare it with the address bar', async () => {
    const root = await render();

    expect(root.querySelector('.host__name')?.textContent).toBe('acme.localhost:7299');
    expect(root.querySelector('.host .hd-kicker')?.textContent).toBe('You are signed in at');
    expect(root.querySelector('.host__check')?.textContent).toContain('address bar');
  });

  it('places the title and the task in the card, and marks the page as a development build', async () => {
    const root = await render();

    expect(root.querySelector('.statement h1')?.textContent).toBe('Title');
    expect(root.querySelector('main .task')?.textContent).toBe('Task');
    expect(root.querySelector('footer')?.textContent).toContain('Development build');
  });

  it('exposes the state as an attribute, and sets aria-busy only while busy', async () => {
    const root = await render();

    expect(root.querySelector('hd-card')?.getAttribute('data-state')).toBe('busy');
    expect(root.querySelector('main')?.getAttribute('aria-busy')).toBe('true');
  });

  it('draws the eye as decoration', async () => {
    const root = await render();

    expect(root.querySelector('.eye')?.getAttribute('aria-hidden')).toBe('true');
  });
});
