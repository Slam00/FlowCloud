package io.github.dovecoteescapee.byedpi.activities

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Filter
import android.widget.TextView
import androidx.annotation.StringRes
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.data.TransportMode

data class TransportOption(
    val mode: TransportMode,
    val title: String,
    val description: String,
) {
    /** The dropdown field shows only the title of the selected option. */
    override fun toString(): String = title

    companion object {
        @StringRes
        fun titleRes(mode: TransportMode): Int = when (mode) {
            TransportMode.Auto -> R.string.mode_auto
            TransportMode.ByeDpi -> R.string.mode_byedpi
            TransportMode.Warp -> R.string.mode_warp
        }

        @StringRes
        fun descriptionRes(mode: TransportMode): Int = when (mode) {
            TransportMode.Auto -> R.string.manual_auto
            TransportMode.ByeDpi -> R.string.manual_byedpi
            TransportMode.Warp -> R.string.manual_warp
        }

        fun all(context: Context): List<TransportOption> = TransportMode.values().map {
            TransportOption(it, context.getString(titleRes(it)), context.getString(descriptionRes(it)))
        }
    }
}

/** Two-line rows (mode and what it does) for the connection mode dropdown. */
class TransportModeAdapter(
    context: Context,
    private val options: List<TransportOption>,
) : ArrayAdapter<TransportOption>(context, R.layout.item_transport_mode, options) {
    private val inflater = LayoutInflater.from(context)

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: inflater.inflate(R.layout.item_transport_mode, parent, false)
        val option = options[position]
        view.findViewById<TextView>(R.id.mode_title).text = option.title
        view.findViewById<TextView>(R.id.mode_description).text = option.description
        return view
    }

    // The field is not editable, so the list must never be narrowed by its text.
    private val showAll = object : Filter() {
        override fun performFiltering(constraint: CharSequence?) = FilterResults().apply {
            values = options
            count = options.size
        }

        override fun publishResults(constraint: CharSequence?, results: FilterResults?) {
            notifyDataSetChanged()
        }

        override fun convertResultToString(resultValue: Any?): CharSequence =
            (resultValue as? TransportOption)?.title ?: ""
    }

    override fun getFilter(): Filter = showAll
}
