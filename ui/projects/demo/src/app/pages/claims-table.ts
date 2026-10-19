import { Component, computed, input } from '@angular/core';

/** Claims as a two-column table. Angular encodes every value, so a claim cannot inject markup. */
@Component({
  selector: 'demo-claims-table',
  styles: `
    :host {
      display: block;
    }
  `,
  template: `
    <table class="hd-table">
      <caption>
        {{
          caption()
        }}
      </caption>
      <thead>
        <tr>
          <th scope="col">Claim</th>
          <th scope="col">Value</th>
          @if (notes()) {
            <th scope="col">{{ notesHeading() }}</th>
          }
        </tr>
      </thead>
      <tbody>
        @for (row of rows(); track row.name) {
          <tr>
            <th scope="row">
              <code>{{ row.name }}</code>
            </th>
            <td>
              <code>{{ row.value }}</code>
            </td>
            @if (notes()) {
              <td>{{ row.note }}</td>
            }
          </tr>
        }
      </tbody>
    </table>
  `,
})
export class ClaimsTable {
  readonly claims = input.required<Record<string, unknown>>();
  readonly caption = input.required<string>();
  /** An optional third column, keyed by claim name. */
  readonly notes = input<Record<string, string>>();
  readonly notesHeading = input('Note');

  protected readonly rows = computed(() =>
    Object.entries(this.claims()).map(([name, value]) => ({
      name,
      value: typeof value === 'string' ? value : JSON.stringify(value),
      note: this.notes()?.[name] ?? '',
    })),
  );
}
